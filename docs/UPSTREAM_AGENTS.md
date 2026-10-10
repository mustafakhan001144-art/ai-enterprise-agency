# Upstream agent repository (`vendor/agency-agents`)

## Current state

`vendor/agency-agents` is **absent** from the cloud workspace and from this
repository. The Windows copy has not been inspected, so it may exist there
(`scripts/inspect-local.ps1` reports which form it takes).

The four custom personas in `core/agents/` are the agency's own work and do not
depend on it. No code in `api/` imports or reads `vendor/`.

## Recommended integration: pinned git submodule

A submodule records one exact upstream commit, so both environments get
identical agent files, upstream history and its MIT `LICENSE` stay intact, and
upgrades are a reviewed one-line change.

Add it once (in whichever environment has network access to the upstream):

```bash
git submodule add <UPSTREAM_URL> vendor/agency-agents
git -C vendor/agency-agents checkout <COMMIT_SHA>
git add .gitmodules vendor/agency-agents
git commit -m "Pin vendor/agency-agents at <COMMIT_SHA>"
```

Then record the URL, commit and licence here:

| Field | Value |
|---|---|
| Upstream URL | _to confirm_ |
| Pinned commit | _to confirm_ |
| Licence | MIT (keep upstream `LICENSE` and copyright notices) |

## If the Windows copy already has it

- **Already a submodule** (`.gitmodules` lists it): keep it; record its commit above.
- **Nested git repo** (has its own `.git`, no `.gitmodules` entry): do not delete
  its `.git`. Note its `remote -v` and `log -1`, then register it with
  `git submodule add <that remote> vendor/agency-agents` pointing at the same commit.
- **Plain directory with local edits**: compare it with upstream first. If it
  was modified, keep the edits on a fork and submodule the fork, or keep it as a
  vendored directory and document the tradeoff (no upstream history, manual updates).

## Commands for both environments

```bash
git clone --recurse-submodules https://github.com/mustafakhan001144-art/ai-enterprise-agency.git
# existing clone:
git submodule update --init --recursive
# after someone bumps the pin:
git pull && git submodule update --init --recursive
```

These are identical in PowerShell and bash. CI checks out submodules recursively.
