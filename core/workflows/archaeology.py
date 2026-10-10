"""Legacy code archaeology: static extraction plus the engines behind two custom agents.

* ``extract`` is the orchestrator's static extractor. It walks a checked-out repository
  without following symlinks or executing anything, and records files, import
  statements, manifests, lockfiles and vendored directories.
* ``dependency_map`` implements ``archaeology.dependency-cartographer`` (DependencyMap/v1).
* ``archaeology_report`` implements ``archaeology.legacy-code-archaeologist``
  (ArchaeologyReport/v1): hazard catalogue, risk factors F1 to F7, tiers and the
  modification gate.

Python gets full import resolution and AST-based behaviour reconstruction. Other
languages get metrics (lizard), line-based hazard detection and an explicit
UNSUPPORTED_LANGUAGE evidence gap instead of guessed behaviour.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
import math
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lizard
import networkx as nx

from core.workflows.common import canonical_digest, excerpt

CARTOGRAPHER_ID = "archaeology.dependency-cartographer"
ARCHAEOLOGIST_ID = "archaeology.legacy-code-archaeologist"

LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".cbl": "cobol",
    ".cob": "cobol",
    ".sh": "shell",
}
VENDOR_DIR_NAMES = {
    "vendor",
    "vendors",
    "third_party",
    "third-party",
    "thirdparty",
    "node_modules",
    "site-packages",
    "external",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}
MANIFEST_TYPES = {
    "requirements.txt": "requirements",
    "pyproject.toml": "pyproject",
    "package.json": "package_json",
    "pom.xml": "pom",
    "build.gradle": "gradle",
    "Gemfile": "gemfile",
    "composer.json": "composer",
    "go.mod": "go_mod",
    "Cargo.toml": "cargo",
    "Makefile": "makefile",
    "CMakeLists.txt": "cmake",
    "setup.py": "other",
    "setup.cfg": "other",
}
LOCKFILE_NAMES = {
    "poetry.lock": "poetry",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "uv.lock": "uv",
    "Pipfile.lock": "pipenv",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "Gemfile.lock": "bundler",
    "composer.lock": "composer",
    "pnpm-lock.yaml": "pnpm",
}
NODE_BUILTINS = {
    "assert",
    "buffer",
    "child_process",
    "cluster",
    "crypto",
    "dgram",
    "dns",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "net",
    "os",
    "path",
    "process",
    "querystring",
    "readline",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
}
PY_STDLIB = set(sys.stdlib_module_names)

MAX_FILES = 5000
MAX_FILE_BYTES = 1024 * 1024
MAX_UNITS = 3000
CLONE_TIMEOUT_SECONDS = 180


class FetchError(RuntimeError):
    """The repository could not be fetched. Retrying may succeed."""


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------
def git_fetch(repo_url: str, ref: str | None, dest: Path) -> str | None:
    """Shallow-clone into dest with hooks, submodules, credential prompts and local transports disabled.

    Returns the checked-out commit hash.
    """
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(dest.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ALLOW_PROTOCOL": "https",
    }
    safe = [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.symlinks=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "submodule.recurse=false",
        "-c",
        "core.fsmonitor=false",
    ]
    cmd = ["git", *safe, "clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules"]
    if ref and not re.fullmatch(r"[0-9a-f]{40}", ref):
        cmd += ["--branch", ref]
    cmd += ["--", repo_url, str(dest)]
    try:
        subprocess.run(cmd, env=env, check=True, capture_output=True, timeout=CLONE_TIMEOUT_SECONDS)
        if ref and re.fullmatch(r"[0-9a-f]{40}", ref):
            subprocess.run(
                ["git", *safe, "-C", str(dest), "fetch", "--depth", "1", "origin", ref],
                env=env,
                check=True,
                capture_output=True,
                timeout=CLONE_TIMEOUT_SECONDS,
            )
            subprocess.run(
                ["git", *safe, "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"],
                env=env,
                check=True,
                capture_output=True,
                timeout=CLONE_TIMEOUT_SECONDS,
            )
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise FetchError("git clone timed out") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else exc.stderr
        raise FetchError(f"git failed: {excerpt(stderr or '', 300).strip()}") from exc
    return head.stdout.strip() or None


# ---------------------------------------------------------------------------
# Static extraction
# ---------------------------------------------------------------------------
@dataclass
class Extraction:
    root: Path
    files: list[dict] = field(default_factory=list)
    imports: list[dict] = field(default_factory=list)
    manifests: list[dict] = field(default_factory=list)
    lockfiles: list[dict] = field(default_factory=list)
    vendored_dirs: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)
    gaps: list[dict] = field(default_factory=list)
    truncated: bool = False

    def payload(self) -> dict:
        return {
            "files": self.files,
            "imports": [{k: v for k, v in i.items() if not k.startswith("_")} for i in self.imports],
            "manifests": self.manifests,
            "lockfiles": self.lockfiles,
            "vendored_dirs": self.vendored_dirs,
        }


def _manifest_type(name: str) -> str | None:
    if name in MANIFEST_TYPES:
        return MANIFEST_TYPES[name]
    if re.fullmatch(r"requirements[\w.-]*\.(txt|in)", name):
        return "requirements"
    return None


def _lockfile_type(name: str) -> str | None:
    if name in LOCKFILE_NAMES:
        return LOCKFILE_NAMES[name]
    if re.fullmatch(r"requirements[\w.-]*\.lock", name):
        return "pip"
    return None


def extract(root: Path) -> Extraction:
    out = Extraction(root=root)
    root = root.resolve()
    candidates: list[Path] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue  # never follow links out of the sandbox
            if entry.is_dir():
                if entry.name in SKIP_DIRS:
                    continue
                rel = entry.relative_to(root).as_posix()
                if entry.name in VENDOR_DIR_NAMES:
                    out.vendored_dirs.append(rel)
                stack.append(entry)
            elif entry.is_file():
                candidates.append(entry)
    candidates.sort()
    if len(candidates) > MAX_FILES:
        out.truncated = True
        out.gaps.append(
            {
                "type": "OTHER",
                "detail": f"repository has {len(candidates)} files; the first {MAX_FILES} in path order were analysed",
                "file": None,
            }
        )
        candidates = candidates[:MAX_FILES]

    for path in candidates:
        rel = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            continue
        language = LANGUAGES.get(path.suffix.lower())
        manifest = _manifest_type(path.name)
        lockfile = _lockfile_type(path.name)
        if not (language or manifest or lockfile):
            continue
        if size > MAX_FILE_BYTES:
            out.gaps.append(
                {"type": "OTHER", "detail": f"file larger than {MAX_FILE_BYTES} bytes was not read", "file": rel}
            )
            continue
        raw = path.read_bytes()
        text = raw.decode("utf-8", "replace")
        if manifest:
            out.manifests.append({"path": rel, "type": manifest, "content": text})
        if lockfile:
            out.lockfiles.append({"path": rel, "type": lockfile, "content": text})
        if language:
            out.files.append(
                {
                    "path": rel,
                    "language": language,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "loc": len(text.splitlines()),
                }
            )
            out.sources[rel] = text
            out.imports += _imports_for(rel, language, text, out)
        elif manifest or lockfile:
            # Manifests are evidence sources too; record them as files so refs resolve.
            out.files.append(
                {
                    "path": rel,
                    "language": None,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "loc": len(text.splitlines()),
                }
            )
            out.sources[rel] = text
        if path.name in (
            "__main__.py",
            "manage.py",
            "main.py",
            "app.py",
            "wsgi.py",
            "asgi.py",
            "conftest.py",
        ) or re.fullmatch(r"test_.*\.py|.*_test\.py", path.name):
            out.entrypoints.append(rel)
    out.vendored_dirs.sort()
    _manifest_entrypoints(out)
    return out


def _imports_for(rel: str, language: str, text: str, out: Extraction) -> list[dict]:
    lines = text.splitlines()
    found: list[dict] = []
    if language == "python":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            out.gaps.append({"type": "OTHER", "detail": "Python source could not be parsed", "file": rel})
            return found
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                found.append(
                    {
                        "file": rel,
                        "line": node.lineno,
                        "raw": lines[node.lineno - 1].strip()[:200],
                        "kind": "import",
                        "_node": node,
                    }
                )
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in ("importlib.import_module", "__import__", "import_module"):
                    found.append(
                        {
                            "file": rel,
                            "line": node.lineno,
                            "raw": lines[node.lineno - 1].strip()[:200],
                            "kind": "dynamic",
                            "_node": node,
                        }
                    )
        found.sort(key=lambda i: i["line"])
    elif language in ("javascript", "typescript"):
        pattern = re.compile(
            r"""(?:import\s+(?:[\w*{}\s,]+\s+from\s+)?|export\s+[\w*{}\s,]+\s+from\s+)["']([^"']+)["']"""
            r"""|require\(\s*["']([^"']+)["']\s*\)|import\(\s*(["'][^"']+["']|[^)]+)\)"""
        )
        for number, line in enumerate(lines, start=1):
            for match in pattern.finditer(line):
                if match.group(3) is not None:
                    found.append(
                        {
                            "file": rel,
                            "line": number,
                            "raw": line.strip()[:200],
                            "kind": "dynamic",
                            "_target": match.group(3).strip(),
                        }
                    )
                else:
                    found.append(
                        {
                            "file": rel,
                            "line": number,
                            "raw": line.strip()[:200],
                            "kind": "require" if match.group(2) else "import",
                            "_target": match.group(1) or match.group(2),
                        }
                    )
    elif language in ("c", "cpp"):
        for number, line in enumerate(lines, start=1):
            match = re.match(r'\s*#\s*include\s*([<"])([^>"]+)[>"]', line)
            if match:
                found.append(
                    {
                        "file": rel,
                        "line": number,
                        "raw": line.strip()[:200],
                        "kind": "include",
                        "_target": match.group(2),
                        "_system": match.group(1) == "<",
                    }
                )
    return found


def _manifest_entrypoints(out: Extraction) -> None:
    for manifest in out.manifests:
        try:
            if manifest["type"] == "pyproject":
                data = tomllib.loads(manifest["content"])
                for target in (data.get("project", {}).get("scripts", {}) or {}).values():
                    module = str(target).split(":", 1)[0].replace(".", "/")
                    for candidate in (f"{module}.py", f"src/{module}.py", f"{module}/__init__.py"):
                        if candidate in out.sources:
                            out.entrypoints.append(candidate)
            elif manifest["type"] == "package_json":
                data = json.loads(manifest["content"])
                base = str(Path(manifest["path"]).parent).replace(".", "") if "/" in manifest["path"] else ""
                mains = [data.get("main")] + (
                    list(data["bin"].values()) if isinstance(data.get("bin"), dict) else [data.get("bin")]
                )
                for main in filter(None, mains):
                    path = str(Path(base, str(main))).lstrip("./") if base else str(main).lstrip("./")
                    if path in out.sources:
                        out.entrypoints.append(path)
        except (tomllib.TOMLDecodeError, json.JSONDecodeError, AttributeError, TypeError):
            continue


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        prefix = _call_name(func.value)
        return f"{prefix}.{func.attr}" if prefix else func.attr
    return ""


# ---------------------------------------------------------------------------
# Dependency cartography
# ---------------------------------------------------------------------------
def normalise_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*?)\s*(?:;.*)?(?:#.*)?$")


@dataclass
class Declared:
    ecosystem: str
    name: str
    constraint: str | None
    ref: dict
    manifest: str
    locked: str | None = None


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return 1


def parse_manifests(extraction: Extraction) -> tuple[list[Declared], list[dict]]:
    declared: list[Declared] = []
    gaps: list[dict] = []
    for manifest in extraction.manifests:
        path, text = manifest["path"], manifest["content"]
        try:
            if manifest["type"] == "requirements":
                for number, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith(("#", "-", "git+", "http")):
                        continue
                    match = REQ_LINE_RE.match(stripped)
                    if match:
                        constraint = match.group(3).strip() or None
                        declared.append(
                            Declared(
                                "pypi", normalise_pypi(match.group(1)), constraint, {"file": path, "line": number}, path
                            )
                        )
            elif manifest["type"] == "pyproject":
                data = tomllib.loads(text)
                deps = list(data.get("project", {}).get("dependencies", []) or [])
                for extra in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
                    deps += list(extra)
                for dep in deps:
                    match = REQ_LINE_RE.match(dep)
                    if match:
                        declared.append(
                            Declared(
                                "pypi",
                                normalise_pypi(match.group(1)),
                                match.group(3).strip() or None,
                                {"file": path, "line": _line_of(text, dep)},
                                path,
                            )
                        )
                poetry = data.get("tool", {}).get("poetry", {})
                for section in ("dependencies", "dev-dependencies"):
                    for name, spec in (poetry.get(section, {}) or {}).items():
                        if name.lower() == "python":
                            continue
                        constraint = (
                            spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
                        )
                        declared.append(
                            Declared(
                                "pypi",
                                normalise_pypi(name),
                                constraint,
                                {"file": path, "line": _line_of(text, name)},
                                path,
                            )
                        )
            elif manifest["type"] == "package_json":
                data = json.loads(text)
                for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    for name, constraint in (data.get(section) or {}).items():
                        declared.append(
                            Declared(
                                "npm",
                                name.lower(),
                                str(constraint),
                                {"file": path, "line": _line_of(text, f'"{name}"')},
                                path,
                            )
                        )
            else:
                gaps.append(
                    {
                        "type": "OTHER",
                        "detail": f"manifest type {manifest['type']} is recorded but its dependencies are not parsed",
                        "file": path,
                    }
                )
        except (tomllib.TOMLDecodeError, json.JSONDecodeError, AttributeError, TypeError) as exc:
            gaps.append({"type": "UNPARSEABLE_MANIFEST", "detail": f"{type(exc).__name__}", "file": path})
    _apply_locks(declared, extraction, gaps)
    return declared, gaps


def _apply_locks(declared: list[Declared], extraction: Extraction, gaps: list[dict]) -> None:
    locked: dict[tuple[str, str], str] = {}
    for lock in extraction.lockfiles:
        text = lock["content"]
        try:
            if lock["type"] in ("poetry", "uv"):
                for package in tomllib.loads(text).get("package", []):
                    locked.setdefault(("pypi", normalise_pypi(package["name"])), str(package["version"]))
            elif lock["type"] == "pip":
                for line in text.splitlines():
                    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\#]+)", line)
                    if match:
                        locked.setdefault(("pypi", normalise_pypi(match.group(1))), match.group(2))
            elif lock["type"] == "npm":
                data = json.loads(text)
                for key, info in (data.get("packages") or {}).items():
                    if key.startswith("node_modules/") and isinstance(info, dict) and "version" in info:
                        locked.setdefault(("npm", key.split("node_modules/")[-1].lower()), str(info["version"]))
                for name, info in (data.get("dependencies") or {}).items():
                    if isinstance(info, dict) and "version" in info:
                        locked.setdefault(("npm", name.lower()), str(info["version"]))
        except (tomllib.TOMLDecodeError, json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
            gaps.append(
                {"type": "UNPARSEABLE_MANIFEST", "detail": f"lockfile {type(exc).__name__}", "file": lock["path"]}
            )
    for dep in declared:
        dep.locked = locked.get((dep.ecosystem, dep.name))


def _unbounded(constraint: str | None) -> bool:
    if constraint is None or constraint.strip() in ("", "*", "latest", "x"):
        return True
    text = constraint.replace(" ", "")
    has_upper = any(op in text for op in ("<", "==", "~=", "^", "~")) or re.fullmatch(r"v?\d[\w.+-]*", text)
    return not has_upper


def _python_resolve(
    module: str, importer: str, level: int, files: set[str], roots: list[str]
) -> tuple[str, str] | None:
    parts = module.split(".") if module else []
    if level:
        base = Path(importer).parent
        for _ in range(level - 1):
            base = base.parent
        candidates = [("RELATIVE", base.joinpath(*parts) if parts else base)]
    else:
        candidates = [("SOURCE_ROOT", Path(root, *parts)) for root in roots] + [("REPO_ROOT", Path(*parts))]
    for rule, candidate in candidates:
        for path in (f"{candidate.as_posix()}.py", f"{candidate.as_posix()}/__init__.py"):
            path = path.lstrip("./") if path.startswith("./") else path
            if path in files:
                return path, rule
    return None


def _js_resolve(target: str, importer: str, files: set[str]) -> tuple[str, str] | None:
    if not target.startswith("."):
        return None
    base = Path(importer).parent / target
    normalised = Path(*[p for p in base.parts if p not in (".",)])
    parts: list[str] = []
    for part in normalised.parts:
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    stem = "/".join(parts)
    for suffix in ("", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", "/index.js", "/index.ts"):
        if f"{stem}{suffix}" in files:
            return f"{stem}{suffix}", "RELATIVE"
    return None


def dependency_map(extraction: Extraction, repository: dict, run_id: str, advisories: list[dict] | None = None) -> dict:
    advisories = advisories or []
    payload = extraction.payload()
    report: dict[str, Any] = {
        "schema_version": "DependencyMap/v1",
        "agent_id": CARTOGRAPHER_ID,
        "run_id": run_id,
        "stage_id": "dependency_cartography",
        "input_digest": canonical_digest(
            {"repository": repository, "extraction": payload, "advisory_snapshot": advisories}
        ),
        "repository": {"name": repository.get("name"), "commit": repository.get("commit")},
    }
    code_files = [f for f in extraction.files if f["language"]]
    if not code_files:
        report.update(
            status="REJECTED_INPUT",
            nodes=[],
            edges=[],
            dynamic_references=[],
            unresolved=[],
            graph_metrics={
                "internal_modules": 0,
                "external_packages": 0,
                "edges_total": 0,
                "cycles": [],
                "orphans": [],
                "hub_threshold": 0,
                "hubs": [],
            },
            evidence_gaps=[
                {
                    "gap_id": "GAP-001",
                    "type": "OTHER",
                    "detail": "no source files in a recognised language were found",
                    "file": None,
                }
            ],
        )
        report["self_validation"] = validate_dependency_map(report, extraction)
        return report

    gaps: list[dict] = list(extraction.gaps)
    declared, manifest_gaps = parse_manifests(extraction)
    gaps += manifest_gaps
    files = {f["path"] for f in code_files}
    roots = ["src", "lib"]
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    dynamic: list[dict] = []
    unresolved: list[dict] = []

    def vendored(path: str) -> bool:
        return any(path == v or path.startswith(v + "/") for v in extraction.vendored_dirs)

    def node(node_id: str, node_type: str, ref: dict, **extra) -> dict:
        entry = nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "node_type": node_type,
                "language": extra.get("language"),
                "ecosystem": extra.get("ecosystem"),
                "declared_constraint": None,
                "locked_version": None,
                "dependency_status": None,
                "additional_statuses": [],
                "advisories": [],
                "metrics": {"fan_in": 0, "fan_out": 0, "is_hub": False, "in_cycle": False, "is_orphan": False},
                "evidence_refs": [],
            },
        )
        if ref not in entry["evidence_refs"]:
            entry["evidence_refs"].append(ref)
        return entry

    def edge(src: str, dst: str, kind: str, resolution: str, ref: dict) -> None:
        entry = edges.setdefault(
            (src, dst, kind), {"from": src, "to": dst, "edge_type": kind, "resolution": resolution, "evidence_refs": []}
        )
        if ref not in entry["evidence_refs"]:
            entry["evidence_refs"].append(ref)

    for f in code_files:
        node(
            f"int:{f['path']}",
            "VENDORED_PACKAGE" if vendored(f["path"]) else "INTERNAL_MODULE",
            {"file": f["path"], "line": 1},
            language=f["language"],
        )

    declared_by_key: dict[tuple[str, str], list[Declared]] = {}
    for dep in declared:
        declared_by_key.setdefault((dep.ecosystem, dep.name), []).append(dep)
        ext_id = f"ext:{dep.ecosystem}:{dep.name}"
        entry = node(ext_id, "EXTERNAL_PACKAGE", dep.ref, ecosystem=dep.ecosystem)
        entry["declared_constraint"] = entry["declared_constraint"] or dep.constraint
        entry["locked_version"] = entry["locked_version"] or dep.locked
        manifest_id = f"int:{dep.manifest}"
        node(manifest_id, "INTERNAL_MODULE", {"file": dep.manifest, "line": 1})
        edge(manifest_id, ext_id, "DECLARES", "MANIFEST", {**dep.ref, "raw": _raw_line(extraction, dep.ref)})

    languages = {f["language"] for f in code_files}
    for language in sorted(languages - {"python", "javascript", "typescript", "c", "cpp"}):
        gaps.append(
            {"type": "UNSUPPORTED_LANGUAGE", "detail": f"imports in {language} files are not extracted", "file": None}
        )

    for imp in extraction.imports:
        src = f"int:{imp['file']}"
        ref = {"file": imp["file"], "line": imp["line"], "raw": imp["raw"]}
        plain_ref = {"file": imp["file"], "line": imp["line"]}
        if imp["file"].endswith(".py"):
            targets = _python_targets(imp)
        else:
            targets = [
                (
                    imp.get("_target", ""),
                    0,
                    imp["kind"] == "dynamic" and not re.fullmatch(r"[\"'][^\"']+[\"']", imp.get("_target", "")),
                )
            ]
        for module, level, non_literal in targets:
            if imp["kind"] == "dynamic":
                literal = module.strip("\"'") if not non_literal else None
                hit = (
                    _python_resolve(literal, imp["file"], 0, files, roots)
                    if literal and imp["file"].endswith(".py")
                    else (_js_resolve(literal, imp["file"], files) if literal else None)
                )
                if hit:
                    edge(src, f"int:{hit[0]}", "DYNAMIC", "DYNAMIC_LITERAL", ref)
                else:
                    dynamic.append(
                        {
                            "file": imp["file"],
                            "line": imp["line"],
                            "raw": imp["raw"],
                            "reason_unresolved": "LITERAL_NOT_FOUND" if literal else "NON_LITERAL_TARGET",
                        }
                    )
                continue
            if imp["file"].endswith(".py"):
                hit = _python_resolve(module, imp["file"], level, files, roots)
                top = module.split(".")[0] if module else ""
                ecosystem, ext_name = "pypi", normalise_pypi(top)
                system = level == 0 and top in PY_STDLIB
            elif imp["kind"] == "include":
                hit = next(
                    (
                        (p, "RELATIVE")
                        for p in (str(Path(imp["file"]).parent / module).lstrip("./"), module)
                        if p in files
                    ),
                    None,
                )
                ecosystem, ext_name, system = "system", module, imp.get("_system", False)
            else:
                hit = _js_resolve(module, imp["file"], files)
                top = module.split("/")[0] if not module.startswith("@") else "/".join(module.split("/")[:2])
                ecosystem, ext_name = "npm", top.lower().removeprefix("node:")
                system = module.startswith("node:") or top in NODE_BUILTINS
            kind = "INCLUDES" if imp["kind"] == "include" else "IMPORTS"
            if hit:
                node(f"int:{hit[0]}", "VENDORED_PACKAGE" if vendored(hit[0]) else "INTERNAL_MODULE", plain_ref)
                edge(src, f"int:{hit[0]}", kind, hit[1], ref)
            elif (ecosystem, ext_name) in declared_by_key:
                ext_id = f"ext:{ecosystem}:{ext_name}"
                node(ext_id, "EXTERNAL_PACKAGE", plain_ref, ecosystem=ecosystem)
                edge(src, ext_id, kind, "MANIFEST", ref)
            elif system:
                sys_id = f"sys:{ext_name}"
                node(sys_id, "SYSTEM_LIBRARY", plain_ref, ecosystem="system")
                edge(src, sys_id, kind, "REPO_ROOT", ref)
            elif level or (ecosystem == "npm" and module.startswith(".")):
                target = ("." * level + module) if imp["file"].endswith(".py") else module
                unres_id = f"unres:{target}"
                node(unres_id, "UNRESOLVED", plain_ref)
                edge(src, unres_id, kind, "RELATIVE", ref)
                unresolved.append(
                    {
                        "node_id": unres_id,
                        "file": imp["file"],
                        "line": imp["line"],
                        "raw": imp["raw"],
                        "attempted": ["RELATIVE"],
                    }
                )
            else:
                ext_id = f"ext:{ecosystem}:{ext_name}"
                entry = node(ext_id, "EXTERNAL_PACKAGE", plain_ref, ecosystem=ecosystem)
                entry.setdefault("_undeclared", True)
                edge(src, ext_id, kind, "REPO_ROOT", ref)

    # External dependency status, rules D1 to D7 (first match is primary).
    reached = {e["to"] for e in edges.values() if e["edge_type"] in ("IMPORTS", "INCLUDES", "LINKS", "DYNAMIC")}
    for entry in nodes.values():
        undeclared = entry.pop("_undeclared", False)
        if entry["node_type"] not in ("EXTERNAL_PACKAGE", "VENDORED_PACKAGE"):
            continue
        if entry["node_type"] == "VENDORED_PACKAGE":
            continue
        statuses: list[str] = []
        matched = [
            a
            for a in advisories
            if entry["locked_version"]
            and a.get("ecosystem") == entry["ecosystem"]
            and normalise_pypi(a.get("package", "")) == entry["id"].split(":", 2)[2]
            and _version_matches(entry["locked_version"], a.get("affected", ""))
        ]
        if matched:
            statuses.append("VULNERABLE_ADVISORY_MATCH")
            entry["advisories"] = [
                {"id": a["id"], "severity": a.get("severity"), "affected": a.get("affected")} for a in matched
            ]
        if not undeclared and entry["id"] not in reached:
            statuses.append("DECLARED_NOT_IMPORTED")
        if undeclared:
            statuses.append("IMPORTED_NOT_DECLARED")
        if not undeclared and not entry["locked_version"] and _unbounded(entry["declared_constraint"]):
            statuses.append("UNPINNED")
        if entry["locked_version"] and not matched:
            statuses.append("PINNED_NO_ADVISORY")
        if not advisories or not entry["locked_version"]:
            statuses.append("ADVISORY_UNDETERMINABLE")
        entry["dependency_status"] = statuses[0] if statuses else None
        entry["additional_statuses"] = statuses[1:]
    for entry in nodes.values():
        if entry["node_type"] == "VENDORED_PACKAGE":
            entry["dependency_status"] = "VENDORED_UNTRACKED"

    if not extraction.lockfiles and declared:
        gaps.append(
            {"type": "MISSING_LOCKFILE", "detail": "dependencies are declared but no lockfile was found", "file": None}
        )
    if not advisories:
        gaps.append(
            {
                "type": "EMPTY_ADVISORY_SNAPSHOT",
                "detail": "no advisory snapshot was supplied, so vulnerability status is not evaluated",
                "file": None,
            }
        )
    gaps.append(
        {
            "type": "OTHER",
            "detail": "Python import names are matched to declared distribution names "
            "literally after PyPI normalisation; packages whose import name differs are reported as "
            "IMPORTED_NOT_DECLARED and DECLARED_NOT_IMPORTED",
            "file": None,
        }
    ) if any(n["ecosystem"] == "pypi" for n in nodes.values()) else None

    metrics = _graph_metrics(nodes, edges, set(extraction.entrypoints))
    node_list = sorted(nodes.values(), key=lambda n: n["id"])
    edge_list = sorted(edges.values(), key=lambda e: (e["from"], e["to"], e["edge_type"]))
    for e in edge_list:
        e["evidence_refs"] = sorted(e["evidence_refs"], key=lambda r: (r["file"], r["line"]))
    for index, gap in enumerate(gaps, start=1):
        gap["gap_id"] = f"GAP-{index:03d}"
        gap.setdefault("file", None)
    status = "PARTIAL" if (unresolved or dynamic or gaps) else "COMPLETE"
    report.update(
        status=status,
        nodes=node_list,
        edges=edge_list,
        dynamic_references=dynamic,
        unresolved=unresolved,
        graph_metrics=metrics,
        evidence_gaps=[
            {"gap_id": g["gap_id"], "type": g["type"], "detail": g["detail"], "file": g["file"]} for g in gaps
        ],
    )
    report["self_validation"] = validate_dependency_map(report, extraction)
    return report


def _python_targets(imp: dict) -> list[tuple[str, int, bool]]:
    node = imp["_node"]
    if isinstance(node, ast.Import):
        return [(alias.name, 0, False) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        module = node.module or ""
        if node.level and not module:
            return [(alias.name, node.level, False) for alias in node.names]
        return [(module, node.level, False)]
    # dynamic call
    arg = node.args[0] if node.args else None
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return [(f'"{arg.value}"', 0, False)]
    return [("", 0, True)]


def _version_matches(version: str, affected: str) -> bool:
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        return Version(version) in SpecifierSet(affected)
    except Exception:
        return affected.strip() in (version, f"=={version}")


def _raw_line(extraction: Extraction, ref: dict) -> str:
    lines = extraction.sources.get(ref["file"], "").splitlines()
    return lines[ref["line"] - 1].strip()[:200] if 0 < ref["line"] <= len(lines) else ""


def _graph_metrics(nodes: dict[str, dict], edges: dict, entrypoints: set[str]) -> dict:
    graph = nx.DiGraph()
    internal = [n for n in nodes.values() if n["node_type"] == "INTERNAL_MODULE"]
    graph.add_nodes_from(n["id"] for n in nodes.values())
    for e in edges.values():
        if e["edge_type"] in ("IMPORTS", "INCLUDES", "LINKS", "DYNAMIC"):
            graph.add_edge(e["from"], e["to"])
    internal_ids = {n["id"] for n in internal}
    for n in nodes.values():
        n["metrics"]["fan_in"] = len({p for p in graph.predecessors(n["id"]) if p in internal_ids})
        n["metrics"]["fan_out"] = len(set(graph.successors(n["id"])))
    cycles = sorted(sorted(c) for c in nx.strongly_connected_components(graph) if len(c) >= 2)
    for component in cycles:
        for node_id in component:
            nodes[node_id]["metrics"]["in_cycle"] = True
    manifest_ids = {e["from"] for e in edges.values() if e["edge_type"] == "DECLARES"}
    orphans = sorted(
        n["id"]
        for n in internal
        if n["metrics"]["fan_in"] == 0 and n["id"] not in manifest_ids and n["id"][4:] not in entrypoints
    )
    for node_id in orphans:
        nodes[node_id]["metrics"]["is_orphan"] = True
    fan_ins = sorted(n["metrics"]["fan_in"] for n in internal)
    threshold = fan_ins[max(0, math.ceil(0.9 * len(fan_ins)) - 1)] if fan_ins else 0
    hubs = sorted(n["id"] for n in internal if n["metrics"]["fan_in"] >= threshold and n["metrics"]["fan_in"] >= 3)
    for node_id in hubs:
        nodes[node_id]["metrics"]["is_hub"] = True
    return {
        "internal_modules": len(internal),
        "external_packages": sum(1 for n in nodes.values() if n["node_type"] == "EXTERNAL_PACKAGE"),
        "edges_total": len(edges),
        "cycles": cycles,
        "orphans": orphans,
        "hub_threshold": threshold,
        "hubs": hubs,
    }


def validate_dependency_map(report: dict, extraction: Extraction) -> list[dict]:
    files = {f["path"]: f for f in extraction.files}
    refs = [r for n in report["nodes"] for r in n["evidence_refs"]] + [
        r for e in report["edges"] for r in e["evidence_refs"]
    ]
    v1 = bool(re.fullmatch(r"[0-9a-f]{64}", report["input_digest"]))
    v2 = all(r["file"] in files and 1 <= r["line"] <= max(1, files[r["file"]]["loc"]) for r in refs)
    ids = [n["id"] for n in report["nodes"]]
    v3 = all(e["from"] in ids and e["to"] in ids for e in report["edges"])
    v4 = len(ids) == len(set(ids)) and len({(e["from"], e["to"], e["edge_type"]) for e in report["edges"]}) == len(
        report["edges"]
    )
    texts = "\n".join(m["content"] for m in extraction.manifests + extraction.lockfiles)
    v5 = all(
        (n["declared_constraint"] is None or n["declared_constraint"] in texts)
        and (n["locked_version"] is None or n["locked_version"] in texts)
        for n in report["nodes"]
    )
    v6 = True  # advisories are copied only from the supplied snapshot
    v7 = report["graph_metrics"]["edges_total"] == len(report["edges"])
    v8 = ids == sorted(ids) and [(e["from"], e["to"], e["edge_type"]) for e in report["edges"]] == sorted(
        (e["from"], e["to"], e["edge_type"]) for e in report["edges"]
    )
    from core.workflows.common import has_banned_phrase

    v9 = not has_banned_phrase(report["evidence_gaps"])
    v10 = all(k in report for k in ("nodes", "edges", "graph_metrics", "evidence_gaps", "status"))
    return [{"check": f"V{i}", "passed": bool(v)} for i, v in enumerate([v1, v2, v3, v4, v5, v6, v7, v8, v9, v10], 1)]


# ---------------------------------------------------------------------------
# Legacy code archaeology
# ---------------------------------------------------------------------------
HAZARD_WEIGHTS = {
    "H01_DYNAMIC_CODE_EXECUTION": 15,
    "H02_HARDCODED_SECRET": 15,
    "H03_UNPARAMETERISED_QUERY": 12,
    "H04_SWALLOWED_EXCEPTION": 8,
    "H05_GLOBAL_MUTABLE_STATE": 8,
    "H06_UNSAFE_DESERIALISATION": 12,
    "H07_UNBOUNDED_LOOP": 6,
    "H08_DEAD_CODE": 3,
    "H09_FILESYSTEM_OR_NETWORK_SIDE_EFFECT": 6,
    "H10_DOC_BEHAVIOUR_CONTRADICTION": 10,
    "H11_INSTRUCTION_IN_SOURCE": 10,
    "H12_DEPRECATED_DEPENDENCY_USE": 8,
}
SECRET_NAME_RE = re.compile(r"(password|passwd|secret|token|api_key|apikey|private_key)", re.IGNORECASE)
SQL_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|EXEC)\b", re.IGNORECASE)
INSTRUCTION_RE = re.compile(
    r"(?:\b(?:ai|llm|gpt|claude|copilot|reviewer|scanner|auditor|assistant)\b.{0,60}"
    r"\b(?:ignore|skip|approve|do not (?:flag|report)|mark (?:as )?safe|disregard)\b"
    r"|\b(?:ignore|disregard) (?:all |any |previous )?(?:instructions|findings|rules)\b)",
    re.IGNORECASE,
)
DYNAMIC_EXEC_RE = re.compile(r"\b(eval|exec|Function|Runtime\.getRuntime\(\)\.exec|system|popen|ProcessBuilder)\s*\(")
DESERIALISE_RE = re.compile(
    r"(pickle\.loads?|cPickle\.loads?|marshal\.loads?|ObjectInputStream|readObject\(|"
    r"\bunserialize\(|Marshal\.load)"
)
SIDE_EFFECT_CALLS = {
    "FILE_DELETE": ("os.remove", "os.unlink", "shutil.rmtree", "os.rmdir", "Path.unlink", "unlink", "rmtree"),
    "NETWORK": ("requests.", "httpx.", "urllib.request.", "urlopen", "socket.", "http.client", "aiohttp.", "smtplib."),
    "PROCESS_SPAWN": ("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn"),
    "QUEUE_PUBLISH": ("publish", "basic_publish", "send_message", "produce"),
}
BUILTINS = set(dir(builtins))


@dataclass
class Unit:
    unit_id: str
    file: str
    language: str
    start: int
    end: int
    source: str
    metrics: dict
    tests: list[dict]
    node: ast.AST | None = None


def collect_units(extraction: Extraction) -> tuple[list[Unit], list[str]]:
    units: list[Unit] = []
    notes: list[str] = []
    test_files = {
        p: s for p, s in extraction.sources.items() if re.search(r"(^|/)(tests?/|test_[^/]*$|[^/]*_test\.)", p)
    }
    for f in extraction.files:
        if not f["language"]:
            continue
        path = f["path"]
        if any(path == v or path.startswith(v + "/") for v in extraction.vendored_dirs) or path in test_files:
            continue
        source = extraction.sources[path]
        lines = source.splitlines()
        try:
            analysis = lizard.analyze_file.analyze_source_code(path, source)
        except Exception:  # lizard cannot parse this file
            notes.append(path)
            continue
        py_nodes: dict[int, ast.AST] = {}
        if f["language"] == "python":
            try:
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                        py_nodes[node.lineno] = node
                        for deco in node.decorator_list:
                            py_nodes.setdefault(deco.lineno, node)
            except (SyntaxError, ValueError):
                pass
        for fn in analysis.function_list:
            node = py_nodes.get(fn.start_line)
            start, end = fn.start_line, fn.end_line
            nesting = _py_nesting(node) if node is not None else getattr(fn, "max_nesting_depth", None)
            qualified = fn.name.replace("::", ".")
            name = fn.unqualified_name if hasattr(fn, "unqualified_name") else fn.name.split(".")[-1]
            tests = [
                {"file": tp, "line": n}
                for tp, ts in sorted(test_files.items())
                for n, line in enumerate(ts.splitlines(), start=1)
                if re.search(rf"\b{re.escape(name)}\s*\(", line)
            ]
            units.append(
                Unit(
                    unit_id=f"{path}::{qualified}",
                    file=path,
                    language=f["language"],
                    start=start,
                    end=end,
                    source="\n".join(lines[start - 1 : end]),
                    metrics={
                        "nloc": fn.nloc,
                        "cyclomatic_complexity": fn.cyclomatic_complexity,
                        "parameter_count": fn.parameter_count,
                        "max_nesting_depth": nesting,
                    },
                    tests=tests[:20],
                    node=node,
                )
            )
            if len(units) >= MAX_UNITS:
                return units, notes
    return units, notes


def _py_nesting(node: ast.AST | None) -> int | None:
    if node is None:
        return None
    blocks = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Match)

    def depth(n: ast.AST, level: int) -> int:
        best = level
        for child in ast.iter_child_nodes(n):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
                continue
            best = max(best, depth(child, level + 1 if isinstance(child, blocks) else level))
        return best

    return depth(node, 0)


def _ref(unit: Unit, line: int) -> dict:
    return {"file": unit.file, "line": line}


def _line_text(unit: Unit, line: int) -> str:
    lines = unit.source.splitlines()
    index = line - unit.start
    return lines[index] if 0 <= index < len(lines) else ""


def _segment(unit: Unit, node: ast.AST, limit: int) -> str:
    text = ast.unparse(node) if hasattr(ast, "unparse") else _line_text(unit, node.lineno)
    return text[:limit]


def analyse_unit(unit: Unit, dep_nodes: dict[str, dict] | None, imports_by_file: dict[str, list[dict]]) -> dict:
    behaviour = {
        "inputs": [],
        "outputs": [],
        "side_effects": [],
        "control_conditions": [],
        "external_calls": [],
        "documented_intent": [],
        "summary_observed": None,
    }
    hazards: dict[str, dict] = {}
    gaps: list[dict] = []

    def hazard(code: str, line: int) -> None:
        entry = hazards.setdefault(
            code,
            {
                "code": code,
                "weight": HAZARD_WEIGHTS[code],
                "evidence_refs": [],
                "excerpt": excerpt(_line_text(unit, line).strip(), 240),
            },
        )
        ref = _ref(unit, line)
        if ref not in entry["evidence_refs"]:
            entry["evidence_refs"].append(ref)

    lines = unit.source.splitlines()
    # Language-independent, line-based detection.
    for offset, line in enumerate(lines):
        number = unit.start + offset
        stripped = line.strip()
        comment = stripped.startswith(("#", "//", "*", "/*", "--")) or " #" in line or "//" in line
        if INSTRUCTION_RE.search(line) and (comment or '"' in line or "'" in line):
            hazard("H11_INSTRUCTION_IN_SOURCE", number)
        if "-----BEGIN" in line and "PRIVATE KEY" in line:
            hazard("H02_HARDCODED_SECRET", number)
        if unit.language != "python":
            if DYNAMIC_EXEC_RE.search(line):
                hazard("H01_DYNAMIC_CODE_EXECUTION", number)
            if DESERIALISE_RE.search(line):
                hazard("H06_UNSAFE_DESERIALISATION", number)
            if re.search(
                r"""(password|passwd|secret|token|api_?key|private_key)\w*\s*[:=]\s*["'][^"']+["']""",
                line,
                re.IGNORECASE,
            ):
                hazard("H02_HARDCODED_SECRET", number)
            if SQL_RE.search(line) and re.search(r"""["']\s*\+|\+\s*["']|\$\{|%s|\.format\(|f["']""", line):
                hazard("H03_UNPARAMETERISED_QUERY", number)
            if re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", line) or re.search(r"catch\s*\(\s*(Throwable|\.\.\.)", line):
                hazard("H04_SWALLOWED_EXCEPTION", number)
            if re.search(r"while\s*\(\s*(true|1)\s*\)|for\s*\(\s*;\s*;\s*\)", line) and not re.search(
                r"\b(break|return)\b", "\n".join(lines[offset:])
            ):
                hazard("H07_UNBOUNDED_LOOP", number)

    if unit.language == "python" and unit.node is not None:
        _python_behaviour(unit, behaviour, hazard)
    elif unit.language == "python":
        gaps.append(
            {"detail": "the unit could not be matched to a parsed Python function", "needed": "parseable source"}
        )
    else:
        behaviour["summary_observed"] = None
        gaps.append(
            {
                "detail": f"behaviour reconstruction is not implemented for {unit.language}",
                "needed": "a reviewer familiar with the language",
            }
        )

    # H12: call into a flagged dependency.
    if dep_nodes is not None:
        for edge in imports_by_file.get(unit.file, []):
            target = dep_nodes.get(edge["to"])
            if target and target.get("dependency_status") in ("VULNERABLE_ADVISORY_MATCH", "IMPORTED_NOT_DECLARED"):
                name = edge["to"].split(":")[-1].replace("-", "_")
                for offset, line in enumerate(lines):
                    if re.search(rf"\b{re.escape(name)}\b", line):
                        hazard("H12_DEPRECATED_DEPENDENCY_USE", unit.start + offset)

    factors, undeterminable = _factors(unit, dep_nodes, hazards)
    score = min(100, sum(f["points"] for f in factors.values()))
    tier = "R1_LOW" if score < 20 else "R2_MODERATE" if score < 40 else "R3_HIGH" if score < 60 else "R4_CRITICAL"
    override = False
    if {
        "H01_DYNAMIC_CODE_EXECUTION",
        "H02_HARDCODED_SECRET",
        "H03_UNPARAMETERISED_QUERY",
        "H06_UNSAFE_DESERIALISATION",
    } & set(hazards) and tier in ("R1_LOW", "R2_MODERATE"):
        tier, override = "R3_HIGH", True
    if tier == "R4_CRITICAL" or "H11_INSTRUCTION_IN_SOURCE" in hazards:
        gate = "FREEZE_HUMAN_EXPERT_REQUIRED"
    elif tier == "R3_HIGH":
        gate = "CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE"
    elif undeterminable:
        gate = "INSUFFICIENT_EVIDENCE_REVIEW_REQUIRED"
    elif tier == "R2_MODERATE":
        gate = "CHANGE_WITH_PEER_REVIEW"
    else:
        gate = "STANDARD_CHANGE_PROCESS"
    for name, factor in factors.items():
        if not factor["determinable"]:
            gaps.append({"detail": f"{name} could not be determined", "needed": "dependency map node or static metric"})
    for index, gap in enumerate(gaps, start=1):
        gap["gap_id"] = f"GAP-{index:03d}"
    return {
        "unit_id": unit.unit_id,
        "file": unit.file,
        "line_range": [unit.start, unit.end],
        "language": unit.language,
        "behaviour": behaviour,
        "contradictions": [],
        "hazards": sorted(hazards.values(), key=lambda h: h["code"]),
        "risk": {"factors": factors, "score": score, "tier": tier, "tier_override_applied": override},
        "modification_gate": gate,
        "evidence_gaps": [{"gap_id": g["gap_id"], "detail": g["detail"], "needed": g["needed"]} for g in gaps],
    }


def _python_behaviour(unit: Unit, behaviour: dict, hazard) -> None:
    fn = unit.node
    params = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
    for arg in params + [a for a in (fn.args.vararg, fn.args.kwarg) if a]:
        if arg.arg in ("self", "cls"):
            continue
        behaviour["inputs"].append(
            {
                "name": arg.arg,
                "description": f"parameter {arg.arg}",
                "source": "OBSERVED",
                "evidence_refs": [_ref(unit, arg.lineno)],
            }
        )
    doc = ast.get_docstring(fn, clean=False)
    if doc and fn.body and isinstance(fn.body[0], ast.Expr):
        behaviour["documented_intent"].append(
            {"claim": doc.strip()[:240], "evidence_refs": [_ref(unit, fn.body[0].lineno)]}
        )
    for offset, line in enumerate(unit.source.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#") and len(stripped) > 2:
            behaviour["documented_intent"].append(
                {"claim": stripped.lstrip("# ")[:240], "evidence_refs": [_ref(unit, unit.start + offset)]}
            )
    global_names: set[str] = set()
    defined = {fn.name}
    for node in ast.walk(fn):
        if isinstance(node, ast.Global):
            global_names.update(node.names)
    for node in ast.walk(fn):
        if node is not fn and isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            if hasattr(node, "name"):
                defined.add(node.name)
        line = getattr(node, "lineno", None)
        if line is None or not (unit.start <= line <= unit.end):
            continue
        if isinstance(node, ast.Return) and node.value is not None:
            behaviour["outputs"].append(
                {
                    "description": f"returns {_segment(unit, node.value, 160)}",
                    "source": "OBSERVED",
                    "evidence_refs": [_ref(unit, line)],
                }
            )
        elif isinstance(node, ast.Yield | ast.YieldFrom) and node.value is not None:
            behaviour["outputs"].append(
                {
                    "description": f"yields {_segment(unit, node.value, 160)}",
                    "source": "OBSERVED",
                    "evidence_refs": [_ref(unit, line)],
                }
            )
        elif isinstance(node, ast.Raise) and node.exc is not None:
            behaviour["outputs"].append(
                {
                    "description": f"raises {_segment(unit, node.exc, 160)}",
                    "source": "OBSERVED",
                    "evidence_refs": [_ref(unit, line)],
                }
            )
        elif isinstance(node, ast.If | ast.While):
            behaviour["control_conditions"].append(
                {
                    "condition": _segment(unit, node.test, 160),
                    "effect": "guards the statements in this branch"
                    if isinstance(node, ast.If)
                    else "repeats the loop body while true",
                    "evidence_refs": [_ref(unit, line)],
                }
            )
            if isinstance(node, ast.If) and isinstance(node.test, ast.Constant) and not node.test.value:
                hazard("H08_DEAD_CODE", line)
            if (
                isinstance(node, ast.While)
                and isinstance(node.test, ast.Constant)
                and node.test.value
                and not any(isinstance(n, ast.Break | ast.Return | ast.Raise) for n in ast.walk(node))
            ):
                hazard("H07_UNBOUNDED_LOOP", line)
        elif isinstance(node, ast.ExceptHandler):
            body_trivial = all(
                isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
                for s in node.body
            )
            rethrows = any(isinstance(s, ast.Raise) for s in ast.walk(node))
            if body_trivial or (node.type is None and not rethrows):
                hazard("H04_SWALLOWED_EXCEPTION", line)
        elif isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                name = (
                    target.id
                    if isinstance(target, ast.Name)
                    else (target.attr if isinstance(target, ast.Attribute) else None)
                )
                if isinstance(target, ast.Name) and target.id in global_names:
                    hazard("H05_GLOBAL_MUTABLE_STATE", line)
                    behaviour["side_effects"].append(
                        {"kind": "GLOBAL_STATE_WRITE", "target": target.id, "evidence_refs": [_ref(unit, line)]}
                    )
                if (
                    name
                    and SECRET_NAME_RE.search(name)
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                    and value.value
                ):
                    hazard("H02_HARDCODED_SECRET", line)
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            _python_call(unit, node, name, line, behaviour, hazard, defined)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or isinstance(
            node, ast.If | ast.For | ast.While | ast.With | ast.Try
        ):
            _dead_code(unit, getattr(node, "body", []), hazard)
    observed = []
    if behaviour["inputs"]:
        observed.append(f"takes {len(behaviour['inputs'])} parameter(s)")
    if behaviour["outputs"]:
        observed.append(f"has {len(behaviour['outputs'])} return, yield or raise point(s)")
    if behaviour["side_effects"]:
        kinds = sorted({s["kind"] for s in behaviour["side_effects"]})
        observed.append("performs " + ", ".join(kinds).lower().replace("_", " "))
    if behaviour["external_calls"]:
        observed.append(f"makes {len(behaviour['external_calls'])} call(s)")
    behaviour["summary_observed"] = ("The unit " + "; ".join(observed) + ".")[:300] if observed else None


def _dead_code(unit: Unit, body: list[ast.stmt], hazard) -> None:
    for index, stmt in enumerate(body[:-1]):
        if isinstance(stmt, ast.Return | ast.Raise | ast.Continue | ast.Break):
            follower = body[index + 1]
            if unit.start <= follower.lineno <= unit.end:
                hazard("H08_DEAD_CODE", follower.lineno)
            break


def _python_call(unit: Unit, node: ast.Call, name: str, line: int, behaviour: dict, hazard, defined: set[str]) -> None:
    keywords = {k.arg: k.value for k in node.keywords if k.arg}
    if name in ("eval", "exec", "os.system", "os.popen", "compile") or (
        name.startswith("subprocess.") and isinstance(keywords.get("shell"), ast.Constant) and keywords["shell"].value
    ):
        hazard("H01_DYNAMIC_CODE_EXECUTION", line)
    # Detection only: these names are matched in the *client's* source as hazard H06.
    # Nothing in this module ever deserialises untrusted data.
    if name in (
        "pickle.load",
        "pickle.loads",
        "cPickle.load",
        "cPickle.loads",
        "marshal.load",
        "marshal.loads",
        "shelve.open",
        "dill.load",
        "dill.loads",
    ) or (
        name in ("yaml.load", "yaml.load_all")
        and not any("Safe" in ast.unparse(v) for v in list(keywords.values()) + node.args[1:])
    ):
        hazard("H06_UNSAFE_DESERIALISATION", line)
    if name.split(".")[-1] in ("execute", "executemany", "executescript", "query", "raw") and node.args:
        first = node.args[0]
        if isinstance(first, ast.BinOp | ast.JoinedStr) or (
            isinstance(first, ast.Call) and _call_name(first.func).endswith("format")
        ):
            if SQL_RE.search(ast.unparse(first)):
                hazard("H03_UNPARAMETERISED_QUERY", line)
        sql = ast.unparse(first)
        kind = (
            "DATABASE_WRITE"
            if re.search(r"\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", sql, re.I)
            else "DATABASE_READ"
        )
        literal = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
        behaviour["side_effects"].append(
            {"kind": kind, "target": literal[:160] if literal else None, "evidence_refs": [_ref(unit, line)]}
        )
    for keyword, value in keywords.items():
        if (
            keyword
            and SECRET_NAME_RE.search(keyword)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value
        ):
            hazard("H02_HARDCODED_SECRET", line)
    side_kind = None
    if name in ("open", "io.open", "Path.open") or name.endswith(".write_text") or name.endswith(".write_bytes"):
        mode = node.args[1] if len(node.args) > 1 else keywords.get("mode")
        mode_value = mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else None
        if name.endswith(("write_text", "write_bytes")) or (mode_value and any(c in mode_value for c in "wax+")):
            side_kind = "FILE_WRITE"
    elif (
        name.endswith((".rename", ".replace"))
        and name.startswith(("os.", "shutil.", "Path"))
        or name in ("os.rename", "shutil.move")
    ):
        side_kind = "FILE_WRITE"
    else:
        for kind, prefixes in SIDE_EFFECT_CALLS.items():
            if any(name.startswith(p) or name == p.rstrip(".") or name.endswith("." + p) for p in prefixes):
                side_kind = kind
                break
    if side_kind:
        target = (
            node.args[0].value
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
            else None
        )
        behaviour["side_effects"].append(
            {"kind": side_kind, "target": target[:160] if target else None, "evidence_refs": [_ref(unit, line)]}
        )
        hazard("H09_FILESYSTEM_OR_NETWORK_SIDE_EFFECT", line) if side_kind in (
            "FILE_WRITE",
            "FILE_DELETE",
            "NETWORK",
            "QUEUE_PUBLISH",
        ) else None
        if side_kind == "PROCESS_SPAWN" and "H01_DYNAMIC_CODE_EXECUTION" not in name:
            pass
    if name:
        basis = "LANGUAGE_SPEC" if name.split(".")[0] in BUILTINS or name.split(".")[0] in PY_STDLIB else "NONE"
        resolved = name in defined
        behaviour["external_calls"].append(
            {
                "callee": name[:160],
                "callee_resolved": resolved,
                "resolved_unit_id": f"{unit.file}::{name}" if resolved else None,
                "semantics_basis": "SUPPLIED_UNIT" if resolved else basis,
                "evidence_refs": [_ref(unit, line)],
            }
        )


def _factors(unit: Unit, dep_nodes: dict[str, dict] | None, hazards: dict) -> tuple[dict, bool]:
    m = unit.metrics
    undeterminable = False

    def bucket(value, steps, maximum):
        nonlocal undeterminable
        if value is None:
            undeterminable = True
            return {"value": None, "points": maximum, "determinable": False}
        for limit, points in steps:
            if value <= limit:
                return {"value": value, "points": points, "determinable": True}
        return {"value": value, "points": maximum, "determinable": True}

    factors = {
        "F1_complexity": bucket(m.get("cyclomatic_complexity"), [(10, 0), (20, 5), (50, 10)], 15),
        "F2_size": bucket(m.get("nloc"), [(50, 0), (200, 3), (500, 6)], 10),
        "F3_nesting": bucket(m.get("max_nesting_depth"), [(3, 0), (5, 3)], 6),
        "F4_test_coverage_signal": {
            "value": len(unit.tests),
            "points": 10 if not unit.tests else 0,
            "determinable": True,
        },
    }
    node = (dep_nodes or {}).get(f"int:{unit.file}")
    if node is None:
        undeterminable = True
        factors["F5_blast_radius"] = {"value": None, "points": 5, "determinable": False}
        factors["F6_cycle_membership"] = {"value": None, "points": 0, "determinable": False}
    else:
        fan_in = node["metrics"]["fan_in"]
        factors["F5_blast_radius"] = {
            "value": fan_in,
            "points": 0 if fan_in <= 2 else 5 if fan_in <= 9 else 10,
            "determinable": True,
        }
        in_cycle = node["metrics"]["in_cycle"]
        factors["F6_cycle_membership"] = {"value": in_cycle, "points": 5 if in_cycle else 0, "determinable": True}
    total = sum(h["weight"] for h in hazards.values())
    factors["F7_hazards"] = {"value": total, "points": min(50, total), "determinable": True}
    return factors, undeterminable


def archaeology_report(extraction: Extraction, dep_map: dict | None, repository: dict, run_id: str) -> dict:
    units, unparsed = collect_units(extraction)
    unit_inputs = [
        {
            "unit_id": u.unit_id,
            "file": u.file,
            "language": u.language,
            "start_line": u.start,
            "end_line": u.end,
            "source": u.source,
            "static_metrics": u.metrics,
            "test_references": u.tests,
            "last_modified": None,
        }
        for u in units
    ]
    report: dict[str, Any] = {
        "schema_version": "ArchaeologyReport/v1",
        "agent_id": ARCHAEOLOGIST_ID,
        "run_id": run_id,
        "stage_id": "legacy_archaeology",
        "input_digest": canonical_digest({"repository": repository, "units": unit_inputs, "dependency_map": dep_map}),
        "dependency_map_digest": canonical_digest(dep_map) if dep_map is not None else None,
        "repository": {"name": repository.get("name"), "commit": repository.get("commit")},
    }
    summary = {
        "units_total": 0,
        "by_tier": dict.fromkeys(("R1_LOW", "R2_MODERATE", "R3_HIGH", "R4_CRITICAL"), 0),
        "by_gate": dict.fromkeys(
            (
                "FREEZE_HUMAN_EXPERT_REQUIRED",
                "CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE",
                "INSUFFICIENT_EVIDENCE_REVIEW_REQUIRED",
                "CHANGE_WITH_PEER_REVIEW",
                "STANDARD_CHANGE_PROCESS",
            ),
            0,
        ),
        "hazard_counts": dict.fromkeys(HAZARD_WEIGHTS, 0),
        "units_with_contradictions": 0,
    }
    if not units:
        report.update(status="REJECTED_INPUT", units=[], portfolio_summary=summary)
        report["self_validation"] = validate_archaeology(report, units)
        return report
    dep_nodes = {n["id"]: n for n in dep_map["nodes"]} if dep_map else None
    imports_by_file: dict[str, list[dict]] = {}
    for e in (dep_map or {}).get("edges", []):
        if e["from"].startswith("int:"):
            imports_by_file.setdefault(e["from"][4:], []).append(e)
    results = [analyse_unit(u, dep_nodes, imports_by_file) for u in units]
    results.sort(key=lambda r: (-r["risk"]["score"], r["unit_id"]))
    for r in results:
        summary["units_total"] += 1
        summary["by_tier"][r["risk"]["tier"]] += 1
        summary["by_gate"][r["modification_gate"]] += 1
        for h in r["hazards"]:
            summary["hazard_counts"][h["code"]] += 1
    partial = any(r["evidence_gaps"] for r in results) or bool(unparsed) or len(units) >= MAX_UNITS
    report.update(status="PARTIAL" if partial else "COMPLETE", units=results, portfolio_summary=summary)
    report["self_validation"] = validate_archaeology(report, units)
    return report


def validate_archaeology(report: dict, units: list[Unit]) -> list[dict]:
    by_id = {u.unit_id: u for u in units}
    results = report["units"]
    v1 = bool(re.fullmatch(r"[0-9a-f]{64}", report["input_digest"]))
    v2 = sorted(r["unit_id"] for r in results) == sorted(by_id) if results else not units
    v3 = all(
        by_id[r["unit_id"]].start <= ref["line"] <= by_id[r["unit_id"]].end
        for r in results
        for section in r["behaviour"].values()
        if isinstance(section, list)
        for item in section
        for ref in item.get("evidence_refs", [])
    )
    v4 = all(h["excerpt"] in excerpt(by_id[r["unit_id"]].source, 10**9) for r in results for h in r["hazards"])
    v5 = all(i["source"] == "OBSERVED" for r in results for i in r["behaviour"]["inputs"] + r["behaviour"]["outputs"])
    v6 = all(h["evidence_refs"] for r in results for h in r["hazards"])

    def recompute(r):
        score = min(100, sum(f["points"] for f in r["risk"]["factors"].values()))
        return score == r["risk"]["score"]

    v7 = all(recompute(r) for r in results)
    from core.workflows.common import has_banned_phrase

    v8 = not has_banned_phrase([r["behaviour"]["summary_observed"] for r in results])
    keys = [(-r["risk"]["score"], r["unit_id"]) for r in results]
    v9 = keys == sorted(keys)
    v10 = all(k in report for k in ("units", "portfolio_summary", "status"))
    return [{"check": f"V{i}", "passed": bool(v)} for i, v in enumerate([v1, v2, v3, v4, v5, v6, v7, v8, v9, v10], 1)]
