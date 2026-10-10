# Development workflow (Windows PC + Claude cloud)

GitHub (`mustafakhan001144-art/ai-enterprise-agency`) is the only sync point.
Uncommitted work never syncs. A push from one environment is not on the other
until that environment fetches it.

## Branches

| Branch | Purpose | Who writes |
|---|---|---|
| `main` | Stable, reviewed, tests green | Merges from `develop` only |
| `develop` | Shared integration branch | Merges from feature branches via PR |
| `feature/local-<task>` | Work done on the Windows PC | Windows only |
| `feature/cloud-<task>` | Work done in Claude cloud | Cloud only |

Rule: **one environment owns a feature branch at a time.** If you must continue
a branch in the other environment, push it first, then fetch it there.
Trivial fixes (typos, docs) may go straight to a short `feature/*` branch and PR.

## Environment setup

| | Windows PowerShell | Cloud / Linux bash |
|---|---|---|
| Python | `py -3.11 -m venv .venv` | `python3.11 -m venv .venv` |
| Activate | `.\.venv\Scripts\Activate.ps1` | `source .venv/bin/activate` |
| Install | `pip install -r requirements.lock` | same |
| Secrets | `Copy-Item .env.example .env` | `cp .env.example .env` |
| Submodules | `git submodule update --init --recursive` | same |
| Tests | `pytest -q` | same |
| Run | `uvicorn api.main:app --reload` | same |

If PowerShell refuses to run `Activate.ps1`:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Database:** SQLite at `AGENCY_DATABASE_PATH` (default `storage/database.db`),
created automatically on startup with `CREATE TABLE IF NOT EXISTS`. There is no
migration tool yet; any schema change must stay additive until one is added.
Each environment has its own local database; databases are never committed.

**External services:** Stripe in TEST mode only during development. Forward
webhooks with the Stripe CLI:
`stripe listen --forward-to localhost:8000/api/v1/webhooks/stripe` and put the
printed `whsec_...` into `.env`.

**Dependencies:** edit `requirements.txt`, then regenerate the lock:
`uv pip compile requirements.txt --universal --python-version 3.11 -o requirements.lock`
(or `pip-compile requirements.txt -o requirements.lock`). Commit both files.

## Start work

```bash
git fetch origin
git switch develop && git pull --ff-only origin develop
git switch -c feature/cloud-<task>      # or feature/local-<task> on Windows
```

## Commit and push

```bash
git status                  # check nothing unexpected (no .env, *.db)
git add <files>             # stage deliberately; avoid `git add -A` on first commits
git diff --cached           # read the staged diff
pytest -q
git commit -m "Describe the change"
git push -u origin feature/cloud-<task>
```

Then open a PR into `develop`. CI must be green before merging.
Promote to `main` with a PR from `develop` when it is stable.

## Switching environments

1. Commit completed work (or a clearly marked `WIP:` commit) and push the branch.
2. In the other environment: `git fetch origin`.
3. `git switch <branch>` and `git pull --ff-only`.
4. If `--ff-only` fails, the branches diverged: see conflicts below.
5. Run `pytest -q` before continuing.

## Integrating others' changes

```bash
git fetch origin
git switch feature/cloud-<task>
git merge origin/develop       # merge, do not rebase shared branches
pytest -q
git push
```

## Resolving conflicts

1. `git status` lists conflicted files.
2. Edit each file, keeping both sides' intent; remove `<<<<<<<`, `=======`, `>>>>>>>`.
3. `git add <file>` for each, then `git commit`.
4. `pytest -q`, then `git push`.

To abandon a merge in progress: `git merge --abort`.
Never `git push --force` to `main`, `develop`, or a branch the other
environment may have touched.

## Recovering an interrupted session

```bash
git status                     # what is uncommitted
git stash list                 # anything stashed earlier
git log --oneline -5           # last local commits
git fetch origin && git status # ahead/behind origin
```

Commit or stash before pulling. If unsure, copy the folder first. To find a
commit you thought was lost: `git reflog`.

## Avoiding accidental overwrites

- Never clone over an existing folder; clone into a new path and compare.
- Never run `git reset --hard`, `git clean -fd`, or `git checkout -- .` on
  work you have not committed or backed up.
- Do not use file-sync tools (OneDrive, Dropbox) on the repo folder in parallel
  with git.
- `.gitattributes` normalises line endings to LF so Windows and Linux commits match.

## Secrets

- `.env` is git-ignored; `.env.example` holds placeholders only.
- Use Stripe test keys in development.
- If a secret is ever committed, **rotate it immediately**. Deleting it in a
  later commit does not remove it from history.
