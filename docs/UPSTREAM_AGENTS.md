# Upstream agent repository (`vendor/agency-agents`)

## Current state

`vendor/agency-agents` is a **git submodule pinned at a single upstream commit**:

| Field | Value |
|---|---|
| Upstream URL | https://github.com/msitarzewski/agency-agents |
| Pinned commit | `f99f6aa910a442b0197b768ce0ea7751e35e2060` (2026-10-08, "fix(eval): parse code fences like lib.sh in the outputs eval (#1055)") |
| Licence | MIT, Copyright (c) 2025 AgentLand Contributors (upstream `LICENSE` kept as is) |

The pin matches the clone found on the Windows PC on 2026-10-10: a plain
`git clone` of upstream `main` at that commit, with no local commits and no
files modified after the clone.

The agency's own personas live in `core/agents/` and do not depend on it. No
code in `api/` reads `vendor/` yet; the dynamic agent registry will.

## Updating the pin

```bash
git -C vendor/agency-agents fetch origin
git -C vendor/agency-agents checkout <NEW_COMMIT_SHA>
git add vendor/agency-agents
git commit -m "Bump vendor/agency-agents to <NEW_COMMIT_SHA>"
```

Do this on a feature branch and open a PR, so the bump is reviewed and CI runs
against the new agent files. Never commit edits inside `vendor/agency-agents`;
if the agency needs changes, fork upstream and point the submodule at the fork.

## Commands for both environments

```bash
git clone --recurse-submodules https://github.com/mustafakhan001144-art/ai-enterprise-agency.git
# existing clone:
git submodule update --init --recursive
# after someone bumps the pin:
git pull && git submodule update --init --recursive
```

These are identical in PowerShell and bash. CI checks out submodules recursively.
