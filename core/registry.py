"""Dynamic agent registry.

Agents are Markdown files with YAML front matter. Two sources are loaded:

* custom agents in ``core/agents/<division>/*.md``. Each must declare ``agent_id``
  (``<division>.<slug>``), ``name``, ``version``, ``output_schema`` and ``description``.
* upstream agents from the pinned ``vendor/agency-agents`` submodule, one division per
  entry in its ``divisions.json``. They need ``name`` and ``description`` and get the id
  ``upstream.<division>.<file stem>``.

The registry re-reads the files whenever their names, sizes or modification times
change, so adding or editing an agent needs no restart. Prompt bodies are hashed, not
exposed: the API publishes metadata and a SHA-256 of each prompt.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CUSTOM_DIVISIONS = ("forensics", "archaeology", "management", "marketing")
REQUIRED_CUSTOM_FIELDS = ("agent_id", "name", "version", "output_schema", "description")


class RegistryError(ValueError):
    """A custom agent file is invalid. Upstream problems are collected as warnings instead."""


@dataclass(frozen=True)
class Agent:
    agent_id: str
    name: str
    division: str
    source: str  # "custom" | "upstream"
    description: str
    path: str  # repo-relative
    prompt_sha256: str
    version: str | None = None
    output_schema: str | None = None
    upstream: tuple[str, ...] = ()
    downstream: tuple[str, ...] = ()

    def public(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "division": self.division,
            "source": self.source,
            "description": self.description,
            "version": self.version,
            "output_schema": self.output_schema,
            "upstream": list(self.upstream),
            "downstream": list(self.downstream),
            "path": self.path,
            "prompt_sha256": self.prompt_sha256,
        }


@dataclass
class Snapshot:
    agents: dict[str, Agent] = field(default_factory=dict)
    divisions: dict[str, dict] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def split_front_matter(text: str) -> tuple[dict, str] | None:
    """Return (front matter, body) or None when the file has no front matter block."""
    if not text.startswith("---"):
        return None
    lines = text.splitlines(keepends=True)
    for index in range(1, len(lines)):
        if lines[index].rstrip("\r\n") == "---":
            meta = yaml.safe_load("".join(lines[1:index])) or {}
            if not isinstance(meta, dict):
                raise ValueError("front matter is not a mapping")
            return meta, "".join(lines[index + 1 :])
    raise ValueError("front matter is not closed")


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list | tuple):
        return tuple(str(v) for v in value)
    return (str(value),)


class AgentRegistry:
    def __init__(self, custom_root: Path, upstream_root: Path | None, repo_root: Path = REPO_ROOT):
        self.custom_root = custom_root
        self.upstream_root = upstream_root
        self.repo_root = repo_root
        self._lock = threading.Lock()
        self._fingerprint: tuple | None = None
        self._snapshot = Snapshot()

    # -- public API -------------------------------------------------------
    def snapshot(self) -> Snapshot:
        fingerprint = self._compute_fingerprint()
        with self._lock:
            if fingerprint != self._fingerprint:
                self._snapshot = self._load()
                self._fingerprint = fingerprint
            return self._snapshot

    def get(self, agent_id: str) -> Agent | None:
        return self.snapshot().agents.get(agent_id)

    def require(self, agent_ids: list[str]) -> list[Agent]:
        snap = self.snapshot()
        missing = [a for a in agent_ids if a not in snap.agents]
        if missing:
            raise RegistryError(f"agents not found in registry: {missing}")
        return [snap.agents[a] for a in agent_ids]

    # -- loading ------------------------------------------------------------
    def _files(self) -> list[Path]:
        files: list[Path] = []
        if self.custom_root.is_dir():
            files += sorted(self.custom_root.glob("*/*.md"))
        if self.upstream_root and self.upstream_root.is_dir():
            index = self.upstream_root / "divisions.json"
            if index.is_file():
                files.append(index)
                for division in self._upstream_divisions(index):
                    files += sorted((self.upstream_root / division).rglob("*.md"))
        return files

    def _compute_fingerprint(self) -> tuple:
        entries = []
        for path in self._files():
            stat = path.stat()
            entries.append((str(path), stat.st_size, stat.st_mtime_ns))
        return tuple(entries)

    @staticmethod
    def _upstream_divisions(index: Path) -> dict[str, dict]:
        data = json.loads(index.read_text(encoding="utf-8"))
        return dict(sorted(data.get("divisions", {}).items()))

    def _relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.repo_root).as_posix()
        except ValueError:
            return path.as_posix()

    def _load(self) -> Snapshot:
        snap = Snapshot()
        for division in CUSTOM_DIVISIONS:
            snap.divisions[division] = {"label": division.title(), "source": "custom", "agent_count": 0}
        self._load_custom(snap)
        self._load_upstream(snap)
        for agent in snap.agents.values():
            snap.divisions[agent.division]["agent_count"] += 1
        for division, info in snap.divisions.items():
            if info["source"] == "custom" and info["agent_count"] == 0:
                snap.warnings.append(f"custom division '{division}' has no agents")
        return snap

    def _load_custom(self, snap: Snapshot) -> None:
        if not self.custom_root.is_dir():
            snap.warnings.append(f"custom agent directory {self.custom_root} does not exist")
            return
        for path in sorted(self.custom_root.glob("*/*.md")):
            division = path.parent.name
            rel = self._relative(path)
            if division not in CUSTOM_DIVISIONS:
                raise RegistryError(f"{rel}: '{division}' is not a custom division {CUSTOM_DIVISIONS}")
            text = path.read_text(encoding="utf-8")
            try:
                parsed = split_front_matter(text)
            except (ValueError, yaml.YAMLError) as exc:
                raise RegistryError(f"{rel}: {exc}") from exc
            if parsed is None:
                raise RegistryError(f"{rel}: missing YAML front matter")
            meta, body = parsed
            missing = [f for f in REQUIRED_CUSTOM_FIELDS if not meta.get(f)]
            if missing:
                raise RegistryError(f"{rel}: missing required fields {missing}")
            agent_id = str(meta["agent_id"])
            if not agent_id.startswith(f"{division}."):
                raise RegistryError(f"{rel}: agent_id '{agent_id}' must start with '{division}.'")
            if agent_id in snap.agents:
                raise RegistryError(f"{rel}: duplicate agent_id '{agent_id}'")
            if not body.strip():
                raise RegistryError(f"{rel}: prompt body is empty")
            snap.agents[agent_id] = Agent(
                agent_id=agent_id,
                name=str(meta["name"]),
                division=division,
                source="custom",
                description=str(meta["description"]).strip(),
                path=rel,
                prompt_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                version=str(meta["version"]),
                output_schema=str(meta["output_schema"]),
                upstream=_as_tuple(meta.get("upstream")),
                downstream=_as_tuple(meta.get("downstream")),
            )

    def _load_upstream(self, snap: Snapshot) -> None:
        if not self.upstream_root or not (self.upstream_root / "divisions.json").is_file():
            snap.warnings.append("upstream agents not loaded: run `git submodule update --init --recursive`")
            return
        for division, info in self._upstream_divisions(self.upstream_root / "divisions.json").items():
            key = f"upstream.{division}"
            snap.divisions[key] = {"label": info.get("label", division), "source": "upstream", "agent_count": 0}
            for path in sorted((self.upstream_root / division).rglob("*.md")):
                rel = self._relative(path)
                text = path.read_text(encoding="utf-8")
                try:
                    parsed = split_front_matter(text)
                except (ValueError, yaml.YAMLError) as exc:
                    snap.warnings.append(f"{rel}: skipped, {exc}")
                    continue
                if parsed is None:
                    continue  # README or guide, not an agent
                meta, _ = parsed
                if not meta.get("name") or not meta.get("description"):
                    snap.warnings.append(f"{rel}: skipped, missing name or description")
                    continue
                agent_id = f"{key}.{path.stem}"
                if agent_id in snap.agents:
                    snap.warnings.append(f"{rel}: skipped, duplicate id {agent_id}")
                    continue
                snap.agents[agent_id] = Agent(
                    agent_id=agent_id,
                    name=str(meta["name"]),
                    division=key,
                    source="upstream",
                    description=str(meta["description"]).strip(),
                    path=rel,
                    prompt_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                )


def default_registry() -> AgentRegistry:
    return AgentRegistry(REPO_ROOT / "core" / "agents", REPO_ROOT / "vendor" / "agency-agents")
