# Recovering and reconciling the Windows copy

Status: **the Windows folder `D:\ai-enterprise-agency` has not been inspected
and is not yet synchronized.** The cloud baseline is on GitHub; these steps fold
the Windows work into it without overwriting either side.

Run everything in **Windows PowerShell**. Nothing below deletes or overwrites a
file in `D:\ai-enterprise-agency`, except steps you choose yourself in step 5.

## 1. Back up first

```powershell
$stamp = Get-Date -Format "yyyyMMdd-HHmm"
robocopy D:\ai-enterprise-agency "D:\ai-enterprise-agency-backup-$stamp" /E /XD .venv venv node_modules __pycache__
```

robocopy exit codes 0-7 mean success. Keep this backup until the merge is done.

## 2. Inspect (read-only)

```powershell
Set-Location D:\ai-enterprise-agency
git --version
git rev-parse --is-inside-work-tree     # "true" = already a repo; error = not a repo
git status
git branch -avv
git log --oneline -20 --all
git remote -v
git stash list
Get-ChildItem -Recurse -File -Force | Where-Object { $_.FullName -notmatch '\\(\.git|\.venv|venv|node_modules|__pycache__)\\' } | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
Get-ChildItem -Recurse -Force -Include .env,*.db,*.sqlite,*.pem,*.key | Select-Object FullName
```

Or run `scripts\inspect-local.ps1` from a clone of the repo, which prints the
same information to `local-inspection.txt` without changing anything.

Share the output in the project thread before continuing if anything looks surprising.

## 3a. If the folder is NOT a git repository

This attaches git to the existing files without touching them. `git reset`
(mixed) moves only the branch pointer and index; the working files stay as they are.

```powershell
Set-Location D:\ai-enterprise-agency
git init
git remote add origin https://github.com/mustafakhan001144-art/ai-enterprise-agency.git
git fetch origin
git symbolic-ref HEAD refs/heads/feature/local-recovery
git reset origin/bootstrap/cloud-baseline     # use origin/develop once it exists
git status
```

If `git status` lists `.gitignore` or `.gitattributes` as `deleted:`, the Windows
folder has none yet; bring them in so `.env` and databases are ignored:

```powershell
git restore -- .gitignore .gitattributes
```

If it lists them as `modified:`, merge the Windows rules into them by hand.

`git status` now shows the real difference between Windows and cloud:

| Shown as | Meaning |
|---|---|
| `modified:` | file exists in both, contents differ |
| `deleted:` | file exists only in the cloud baseline |
| `Untracked files:` | file exists only on Windows |

## 3b. If the folder IS already a git repository

```powershell
Set-Location D:\ai-enterprise-agency
git status                                    # commit or stash anything uncommitted first:
git switch -c feature/local-recovery
git add -A; git status                        # review: no .env, *.db, .venv
git commit -m "Snapshot Windows implementation before reconciliation"
git remote -v                                 # if origin is another URL, use the name "cloud" below
git remote add cloud https://github.com/mustafakhan001144-art/ai-enterprise-agency.git
git fetch cloud
git merge cloud/bootstrap/cloud-baseline --allow-unrelated-histories
git status                                    # conflicted files are listed as "both added"/"both modified"
```

If `origin` already points at this GitHub repo, use `origin` instead of `cloud`.

## 4. Before staging anything

```powershell
git check-ignore -v .env storage\database.db  # both should be listed as ignored
git status --ignored
```

If `.env` or a database file is **not** ignored, stop and fix `.gitignore` first.

## 5. Reconcile file by file

```powershell
git diff -- api/routes/jobs.py               # inspect one modified file
git diff --ignore-cr-at-eol --stat           # hide line-ending-only differences
```

For each file decide:

- **Windows version is better:** keep it, `git add <file>`.
- **Cloud version is better:** `git restore <file>` (this replaces the Windows file;
  it is still in the backup from step 1).
- **Both have value:** edit the file to combine them, then `git add <file>`.
- **Only in cloud (`deleted:`):** `git restore <file>` to bring it to Windows.
- **Only on Windows (untracked):** `git add <file>` if it is source, tests or docs.

Then:

```powershell
git diff --cached --stat
git diff --cached                             # read the whole staged diff
py -3.11 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.lock
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
pytest -q
git commit -m "Reconcile Windows implementation with cloud baseline"
git push -u origin feature/local-recovery
```

The `.env` line only creates the file when it is missing.

Open a pull request from `feature/local-recovery` into the baseline branch on
GitHub. After it merges, both environments follow
[DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md).

## 6. Verify the sync

```powershell
git fetch origin
git status                                    # "up to date with 'origin/...'"
git rev-parse HEAD
git rev-parse origin/feature/local-recovery   # must match
```

The Windows copy counts as synchronized only when these hashes match and the
cloud side has fetched the same commit.
