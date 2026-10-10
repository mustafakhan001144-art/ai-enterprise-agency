# Read-only inspection of a local working copy. Changes nothing.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\inspect-local.ps1 -Path D:\ai-enterprise-agency
param([string]$Path = "D:\ai-enterprise-agency")

$out = Join-Path (Get-Location) "local-inspection.txt"
$skip = '\\(\.git|\.venv|venv|node_modules|__pycache__)(\\|$)'

& {
    "=== Inspection of $Path at $(Get-Date -Format o)"
    "=== git version"; git --version
    Push-Location $Path
    try {
        "=== is git repo"; git rev-parse --is-inside-work-tree 2>&1
        "=== status"; git status 2>&1
        "=== branches"; git branch -avv 2>&1
        "=== log"; git log --oneline -20 --all 2>&1
        "=== remotes"; git remote -v 2>&1
        "=== stashes"; git stash list 2>&1
        "=== submodules"; git submodule status 2>&1
        "=== files (excluding .git, venvs, caches)"
        Get-ChildItem -Recurse -File -Force |
            Where-Object { $_.FullName -notmatch $skip } |
            ForEach-Object { "{0,10}  {1:yyyy-MM-dd HH:mm}  {2}" -f $_.Length, $_.LastWriteTime, $_.FullName.Substring($Path.Length) }
        "=== sensitive file names present (contents NOT printed)"
        Get-ChildItem -Recurse -File -Force -Include .env, .env.*, *.db, *.sqlite, *.sqlite3, *.pem, *.key, *.p12 |
            Where-Object { $_.FullName -notmatch $skip } |
            ForEach-Object { $_.FullName }
        "=== vendor/agency-agents"
        if (Test-Path vendor\agency-agents) {
            if (Test-Path vendor\agency-agents\.git) { "nested git repo or submodule:"; git -C vendor\agency-agents log -1 --format="%H %s" 2>&1; git -C vendor\agency-agents remote -v 2>&1 }
            else { "plain directory" }
        } else { "absent" }
    } finally { Pop-Location }
} *>&1 | Tee-Object -FilePath $out

Write-Host "`nWrote $out"
