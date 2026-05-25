#!/usr/bin/env bash
#
# access-control-probe.sh — inventory-driven access-control test for the
# dioxus-fullstack-example. The higher-signal companion to ffuf-discover.sh:
# instead of *guessing* hidden paths, it probes every endpoint we KNOW exists
# and asserts each one's authorization posture.
#
# AUTHORIZED TESTING ONLY — run against a local instance you own.
#
# The endpoint inventory below was generated from the dioxus MCP tooling
# (route_map + openapi_spec + project_index) against:
#   - examples/dioxus-fullstack-example/src/main.rs   (get_permissions)
#   - crates/arium-dioxus/src/server.rs               (the auth library surface)
# Regenerate it if the server-fn set changes (grep '#\[(get|post)\(' server.rs).
#
# What it checks (this is what fuzzing CANNOT do):
#   PHASE 1  unauth — every PROTECTED / ADMIN endpoint must DENY an anonymous
#                     caller. A 200 carrying real data = Broken Access Control.
#   PHASE 2  authed — (optional, needs a non-admin login) every ADMIN endpoint
#                     must REFUSE a logged-in non-admin. A 200 = privilege
#                     escalation. Set NONADMIN_EMAIL / NONADMIN_PASS to enable.
#   Plus:    PUBLIC endpoints must be reachable (not 404 — proves the inventory
#            is accurate), and /api/user/profile must report is_authenticated
#            =false for an anonymous caller (no identity leak).
#
# Gating model (read from server.rs, so assertions match reality):
#   Protected fns reject anon with Err(ServerFnError::new("Not signed in.")).
#   Admin fns go through require_admin_perm -> "Not signed in." (anon) or
#   "You don't have permission for this action." (authed, no perm).
#   Dioxus surfaces these ServerFnErrors as a non-2xx with the message in the
#   body — NOT as a clean 401/403 — so we assert "denied", not a status number.
#
# Start the server first:
#     DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve
#
set -uo pipefail

# ---- config (env-overridable) ----------------------------------------------
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
BASE="http://${HOST}:${PORT}"

# Optional PHASE 2 creds. A NON-admin account. If it doesn't exist the script
# tries to register it first (harmless on a local test DB).
NONADMIN_EMAIL="${NONADMIN_EMAIL:-}"
NONADMIN_PASS="${NONADMIN_PASS:-Probe-NonAdmin-1!}"

JAR="$(mktemp)"
BODYFILE="$(mktemp)"
trap 'rm -f "$JAR" "$BODYFILE"' EXIT

# Markers that prove the *auth gate itself* rejected us (strongest signal).
DENY_RE='Not signed in|don.?t have permission|permission for this action|Unauthorized|Forbidden|not authenticated'

pass=0; fail=0

# ---- endpoint inventory (METHOD|PATH|BODY) ----------------------------------
# Bodies are arg-shaped JSON (Dioxus JSON codec keys args by name) so the
# request reaches the auth gate instead of dying in arg deserialization.

# Require a signed-in (non-anonymous) user:
PROTECTED=(
  "POST|/api/user/mfa/setup|{}"
  "POST|/api/user/mfa/confirm|{\"code\":\"000000\"}"
  "POST|/api/user/mfa/disable|{}"
  "POST|/api/user/tokens/new|{\"name\":\"probe\"}"
  "GET|/api/user/tokens|"
  "POST|/api/user/tokens/revoke|{\"token_id\":1}"
  "POST|/api/user/verify-mfa|{\"code\":\"000000\"}"
  "GET|/api/account|"
  "POST|/api/account/display-name|{\"new_name\":\"probe\"}"
  "POST|/api/account/password|{\"current\":\"x\",\"new_password\":\"probeprobe1\"}"
  "POST|/api/account/delete|{}"
  "GET|/api/user/permissions|"
)

# Require an "admin:*" permission (also reject anon):
ADMIN=(
  "GET|/api/admin/users?limit=10&offset=0|"
  "GET|/api/admin/users/get?user_id=1|"
  "POST|/api/admin/users/roles|{\"user_id\":1,\"role_ids\":[]}"
  "POST|/api/admin/users/delete|{\"user_id\":1}"
  "POST|/api/admin/audit/query|{\"query\":{\"event_type\":\"\",\"limit\":10,\"offset\":0}}"
  "GET|/api/admin/roles|"
  "POST|/api/admin/roles/create|{\"name\":\"probe\",\"description\":null,\"permissions\":[]}"
  "POST|/api/admin/roles/update|{\"role_id\":1,\"name\":\"probe\",\"description\":null,\"permissions\":[]}"
  "POST|/api/admin/roles/delete|{\"role_id\":1}"
)

# Intentionally open. Non-mutating probes only (no register/reset side effects):
PUBLIC=(
  "GET|/api/auth/providers|"
  "POST|/api/user/login-password|{\"email\":\"nobody@example.invalid\",\"password\":\"x\",\"remember_me\":false}"
  "POST|/api/user/request-password-reset|{\"email\":\"nobody@example.invalid\"}"
  "POST|/api/user/verify-email|{\"token\":\"definitely-not-valid\"}"
)

# ---- helpers ----------------------------------------------------------------
# The server rate-limits via tower_governor (default burst=30, per_second=1).
# A fast run drains the burst bucket and then gets 429s — which would mask the
# auth gate. So probe() transparently waits out a 429 and retries, ensuring
# every request actually reaches its authorization check.
RL_REFILL="${RL_REFILL:-1.2}"   # seconds to wait per 429 (≈ 1 token/sec refill)
RL_MAX_RETRY="${RL_MAX_RETRY:-6}"

# probe METHOD PATH BODY [extra curl args...] -> echoes HTTP status; body in $BODYFILE
probe() {
  local method="$1" path="$2" body="$3"; shift 3
  local code tries=0
  while :; do
    if [[ "$method" == "GET" ]]; then
      code="$(curl -sS -o "$BODYFILE" -w '%{http_code}' --max-time 10 \
              -X GET "${BASE}${path}" "$@" 2>/dev/null)"
    else
      code="$(curl -sS -o "$BODYFILE" -w '%{http_code}' --max-time 10 \
              -X "$method" "${BASE}${path}" \
              -H 'Content-Type: application/json' --data "$body" "$@" 2>/dev/null)"
    fi
    if [[ "$code" == "429" && "$tries" -lt "$RL_MAX_RETRY" ]]; then
      ((tries++)); sleep "$RL_REFILL"; continue
    fi
    break
  done
  echo "$code"
}

snippet() { tr -d '\n' < "$BODYFILE" | cut -c1-90; }

# Assert an anonymous/unauthorized call was DENIED. $1=label for context.
assert_denied() {
  local code="$1"
  local body; body="$(tr -d '\n' < "$BODYFILE")"
  if [[ "$code" == "429" ]]; then
    echo "    WARN  [429] still rate-limited after retries — gate NOT verified (raise RL_MAX_RETRY)"; ((fail++)); return
  fi
  if grep -qiE "$DENY_RE" <<<"$body"; then
    echo "    PASS  [$code] denied at auth gate — $(snippet)"; ((pass++)); return
  fi
  if [[ ! "$code" =~ ^2 ]]; then
    echo "    PASS  [$code] rejected (non-2xx; no gate marker) — $(snippet)"; ((pass++)); return
  fi
  echo "    FAIL  [$code] *** 2xx WITH BODY — POSSIBLE DATA LEAK *** — $(snippet)"; ((fail++))
}

run_group() {
  local title="$1"; shift
  echo; echo "=== $title ==="
  local entry method path body code
  for entry in "$@"; do
    IFS='|' read -r method path body <<<"$entry"
    printf '  %-4s %s\n' "$method" "$path"
    code="$(probe "$method" "$path" "$body")"
    assert_denied "$code"
  done
}

# ---- preflight --------------------------------------------------------------
command -v curl >/dev/null 2>&1 || { echo "error: curl required." >&2; exit 1; }
# A 429 here still proves the server is up (just rate-limited from a prior run).
pre="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${BASE}/" 2>/dev/null)"
if [[ -z "$pre" || "$pre" == "000" ]]; then
  echo "error: ${BASE}/ not responding. Start it: DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve" >&2
  exit 1
fi
echo "target: ${BASE} (preflight ${pre})"

# arium grants the `admin` role to the FIRST account on a fresh DB
# (auth::maybe_grant_first_admin — "first-user-wins" when no admin exists yet).
# So on a clean database the first registrant becomes admin, which would make
# Phase 2's "non-admin" secretly an admin and mask real privilege escalation.
# Claim that slot up front with a sacrificial admin so every test user below is
# a genuine non-admin. Harmless on a populated DB: an admin already exists, so
# this just registers (or no-ops on) an ordinary account. No cookie is saved,
# so Phase 1 still runs fully anonymous.
probe POST /api/user/register-password \
      "$(printf '{"email":"probe-bootstrap-admin@example.com","password":"%s"}' "$NONADMIN_PASS")" >/dev/null

# ---- PHASE 1: anonymous caller must be denied -------------------------------
run_group "PHASE 1a — PROTECTED endpoints, ANONYMOUS (must deny)" "${PROTECTED[@]}"
run_group "PHASE 1b — ADMIN endpoints, ANONYMOUS (must deny)"     "${ADMIN[@]}"

# PUBLIC reachability: must NOT be 404 (proves inventory paths are real & mounted).
echo; echo "=== PHASE 1c — PUBLIC endpoints reachable (must not 404) ==="
for entry in "${PUBLIC[@]}"; do
  IFS='|' read -r method path body <<<"$entry"
  printf '  %-4s %s\n' "$method" "$path"
  code="$(probe "$method" "$path" "$body")"
  if [[ "$code" == "404" ]]; then
    echo "    FAIL  [404] not mounted — inventory drift or wrong path"; ((fail++))
  else
    echo "    PASS  [$code] reachable"; ((pass++))
  fi
done

# Identity-leak check: anon profile must say is_authenticated:false.
echo; echo "=== PHASE 1d — /api/user/profile must not leak identity to anon ==="
code="$(probe GET /api/user/profile "")"
body="$(tr -d '\n' < "$BODYFILE")"
printf '  %-4s %s\n' "GET" "/api/user/profile"
if grep -qiE '"is_authenticated"[[:space:]]*:[[:space:]]*true|"authenticated"[[:space:]]*:[[:space:]]*true' <<<"$body"; then
  echo "    FAIL  [$code] *** anon got an AUTHENTICATED profile *** — $(snippet)"; ((fail++))
elif [[ "$code" =~ ^2 ]]; then
  echo "    PASS  [$code] anonymous profile (is_authenticated:false)"; ((pass++))
else
  echo "    PASS  [$code] denied — $(snippet)"; ((pass++))
fi

# Endpoints that intentionally TOLERATE an anonymous caller and return a benign
# default (same design as /api/user/profile). The test here is that they return
# the *default*, never a real user's state.
echo; echo "=== PHASE 1e — anon-tolerant endpoints must return a benign default ==="

printf '  %-4s %s\n' "POST" "/api/user/logout"   # idempotent no-op for anon
code="$(probe POST /api/user/logout "{}")"
body="$(tr -d '\n' < "$BODYFILE")"
if [[ "$code" =~ ^2 ]] && [[ "$body" =~ ^(null|\{\}|)$ ]]; then
  echo "    PASS  [$code] no-op for anon — $(snippet)"; ((pass++))
elif [[ ! "$code" =~ ^2 ]]; then
  echo "    PASS  [$code] denied — $(snippet)"; ((pass++))
else
  echo "    FAIL  [$code] *** logout returned non-empty body to anon *** — $(snippet)"; ((fail++))
fi

printf '  %-4s %s\n' "GET" "/api/user/mfa/status"   # must be "Disabled", never a real state
code="$(probe GET /api/user/mfa/status "")"
body="$(tr -d '\n' < "$BODYFILE")"
if grep -qiE 'Enabled|Pending' <<<"$body"; then
  echo "    FAIL  [$code] *** leaked MFA state to anon *** — $(snippet)"; ((fail++))
elif [[ "$code" =~ ^2 ]] && grep -qi 'Disabled' <<<"$body"; then
  echo "    PASS  [$code] benign default (Disabled)"; ((pass++))
elif [[ ! "$code" =~ ^2 ]]; then
  echo "    PASS  [$code] denied — $(snippet)"; ((pass++))
else
  echo "    FAIL  [$code] *** unexpected body to anon *** — $(snippet)"; ((fail++))
fi

# ---- PHASE 2 (optional): logged-in non-admin must NOT reach admin endpoints --
echo
if [[ -n "$NONADMIN_EMAIL" ]]; then
  echo "=== PHASE 2 — ADMIN endpoints as a LOGGED-IN NON-ADMIN (must refuse) ==="
  # Ensure the account exists (idempotent on a local test DB), then log in.
  # Routed through probe() so they ride the same 429-retry as everything else.
  probe POST /api/user/register-password \
        "$(printf '{"email":"%s","password":"%s"}' "$NONADMIN_EMAIL" "$NONADMIN_PASS")" >/dev/null
  login_code="$(probe POST /api/user/login-password \
        "$(printf '{"email":"%s","password":"%s","remember_me":false}' "$NONADMIN_EMAIL" "$NONADMIN_PASS")" \
        -c "$JAR")"
  if [[ "$login_code" =~ ^2 ]] && grep -q 'session' "$JAR" 2>/dev/null; then
    echo "  logged in as ${NONADMIN_EMAIL} (cookie captured)"
    for entry in "${ADMIN[@]}"; do
      IFS='|' read -r method path body <<<"$entry"
      printf '  %-4s %s\n' "$method" "$path"
      code="$(probe "$method" "$path" "$body" -b "$JAR")"
      assert_denied "$code"   # expect "don't have permission"
    done
  else
    echo "  SKIP  could not log in as ${NONADMIN_EMAIL} [login HTTP ${login_code}]."
    echo "        Seed a non-admin account or check NONADMIN_PASS. (Body: $(snippet))"
  fi
else
  echo "=== PHASE 2 — skipped (set NONADMIN_EMAIL / NONADMIN_PASS to run the"
  echo "    privilege-escalation check: a non-admin must be refused on /api/admin/*) ==="
fi

# ---- PHASE 3: horizontal isolation (IDOR) -----------------------------------
# Vertical checks (anon->user, non-admin->admin) above prove WHO may call an
# endpoint. This proves a caller can't reach ANOTHER user's object by id.
# arium's only user-scoped foreign-id endpoint is tokens/revoke(token_id); it
# must filter by the caller's user_id, so user B cannot revoke user A's token.
# Needs DX_AUTH_SKIP_EMAIL_VERIFICATION=1 (so fresh logins get a session) and
# the `tokens` feature; self-skips otherwise.
echo
echo "=== PHASE 3 — horizontal isolation: B must not revoke A's API token (IDOR) ==="
# Fresh emails per run so registration always creates the account with a known
# password (avoids password mismatch against a pre-existing account).
ir="$RANDOM-$$"
IA="probe-idor-a-$ir@example.com"; IB="probe-idor-b-$ir@example.com"; IPW="Idor-Probe-1!"
JA="$(mktemp)"; JB="$(mktemp)"
login_as() { # email jar -> echoes "ok" only if the session is TRULY authenticated
  probe POST /api/user/register-password "$(printf '{"email":"%s","password":"%s"}' "$1" "$IPW")" >/dev/null
  probe POST /api/user/login-password \
        "$(printf '{"email":"%s","password":"%s","remember_me":false}' "$1" "$IPW")" -c "$2" >/dev/null
  # Gate on LoginOutcome == "LoggedIn", not cookie presence — anon sessions also
  # get a `session` cookie, so a cookie alone doesn't prove authentication.
  grep -qi 'LoggedIn' "$BODYFILE" && echo ok
}
if [[ "$(login_as "$IA" "$JA")" == ok && "$(login_as "$IB" "$JB")" == ok ]]; then
  probe POST /api/user/tokens/new '{"name":"idor-probe-victim"}' -b "$JA" >/dev/null
  tid="$(grep -oE '"id":[0-9]+' "$BODYFILE" | head -1 | grep -oE '[0-9]+')"
  if [[ -z "$tid" ]]; then
    echo "  SKIP  couldn't create/parse A's token (is the 'tokens' feature on?) — $(snippet)"
  else
    printf '  %-4s %s  (A token_id=%s)\n' "POST" "/api/user/tokens/revoke" "$tid"
    code="$(probe POST /api/user/tokens/revoke "{\"token_id\":$tid}" -b "$JB")"   # B attacks
    bbody="$(tr -d '\n' < "$BODYFILE")"
    # Control: A revokes own token — proves the id was real & revoke works, so a
    # B-failure is genuine ownership scoping, not a bogus id.
    ctrl="$(probe POST /api/user/tokens/revoke "{\"token_id\":$tid}" -b "$JA")"
    if [[ "$code" =~ ^2 && "$bbody" =~ ^(null|\{\}|)$ ]]; then
      echo "    FAIL  [$code] *** B REVOKED A'S TOKEN — IDOR *** — $bbody"; ((fail++))
    elif [[ "$ctrl" =~ ^2 ]]; then
      echo "    PASS  [$code] B refused ($(echo "$bbody" | cut -c1-50)); control: A revoked own token [$ctrl]"; ((pass++))
    else
      echo "    WARN  B refused [$code] but control revoke also failed [$ctrl] — inconclusive (token id may be stale)"; ((fail++))
    fi
  fi
else
  echo "  SKIP  couldn't log in two test users — set DX_AUTH_SKIP_EMAIL_VERIFICATION=1 on the server."
fi
rm -f "$JA" "$JB"

# ---- verdict ----------------------------------------------------------------
echo
echo "============================================================"
echo "  PASS: ${pass}    FAIL: ${fail}"
if [[ "$fail" -gt 0 ]]; then
  echo "  RESULT: FAIL — review the *** lines above (access-control gaps)."
  echo "============================================================"
  exit 1
fi
echo "  RESULT: PASS — every protected endpoint denied unauthorized access."
echo "============================================================"
