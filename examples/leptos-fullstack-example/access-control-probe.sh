#!/usr/bin/env bash
#
# access-control-probe.sh — inventory-driven access-control test for the
# leptos-fullstack-example. The Leptos counterpart of the Dioxus probe; it
# asserts the same three properties against arium-leptos's server fns.
#
# AUTHORIZED TESTING ONLY — run against a local instance you own.
#
# Leptos differences from the Dioxus probe (verified against this example):
#   - Every server fn is mounted POST at /api/{endpoint} (handle_server_fns),
#     so this probe POSTs everything — there are no GET endpoints.
#   - server_fn's default input codec is `PostUrl`, i.e.
#     application/x-www-form-urlencoded — NOT JSON. Bodies here are form fields
#     (`a=1&b=2`); a JSON body fails arg deserialization ("Args|missing field").
#   - Errors surface as wire-500 with a `Type|message` body (e.g.
#     "ServerError|Not signed in."), not JSON — but the message text is present,
#     so the same denial markers match.
#
# Endpoint inventory generated from crates/arium-leptos/src/server.rs. Same auth
# gates and the same arium `maybe_grant_first_admin` first-user-wins bootstrap
# as the Dioxus side, so the sacrificial-admin preamble below applies identically.
#
# Start the server first (default site-addr is 127.0.0.1:3000):
#     DX_AUTH_SKIP_EMAIL_VERIFICATION=1 cargo leptos serve     # or the built bin
#
set -uo pipefail

# ---- config (env-overridable) ----------------------------------------------
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-3000}"                  # leptos site-addr default
ROOT="http://${HOST}:${PORT}"
BASE="${ROOT}/api"                    # handle_server_fns mount point

NONADMIN_EMAIL="${NONADMIN_EMAIL:-}"
NONADMIN_PASS="${NONADMIN_PASS:-Probe-NonAdmin-1!}"

JAR="$(mktemp)"; BODYFILE="$(mktemp)"
trap 'rm -f "$JAR" "$BODYFILE"' EXIT

DENY_RE='Not signed in|don.?t have permission|permission for this action|Unauthorized|Forbidden|not authenticated'
pass=0; fail=0

RL_REFILL="${RL_REFILL:-1.2}"         # tower_governor: ~1 token/sec refill
RL_MAX_RETRY="${RL_MAX_RETRY:-6}"

# urlencode just the '@' in an email (enough for form-value position).
enc() { printf '%s' "${1//@/%40}"; }

# ---- endpoint inventory (PATH|form-body) ------------------------------------
# Paths are relative to /api. Bodies are urlencoded form fields so requests
# reach the auth gate instead of dying in arg deserialization.

PROTECTED=(            # require a signed-in (non-anonymous) user
  "/user/mfa/setup|"
  "/user/mfa/confirm|code=000000"
  "/user/mfa/disable|"
  "/user/tokens/new|name=probe"
  "/user/tokens|"
  "/user/tokens/revoke|token_id=1"
  "/user/verify-mfa|code=000000"
  "/account|"
  "/account/display-name|new_name=probe"
  "/account/password|current=x&new_password=probeprobe1"
  "/account/delete|"
)

ADMIN=(               # require an admin:* permission (also reject anon)
  "/admin/users|limit=10&offset=0"
  "/admin/users/get|user_id=1"
  # Vec/struct args use serde_qs bracket encoding so the body deserializes and
  # the request reaches require_admin_perm — otherwise a missing-field error
  # would mask the gate (and hide its removal in a future refactor).
  "/admin/users/roles|user_id=1&role_ids[0]=1"
  "/admin/users/delete|user_id=1"
  "/admin/audit/query|query[event_type]=&query[limit]=10&query[offset]=0"
  "/admin/roles|"
  "/admin/roles/create|name=probe&permissions[0]=x"
  "/admin/roles/update|role_id=1&name=probe&permissions[0]=x"
  "/admin/roles/delete|role_id=1"
)

PUBLIC=(              # intentionally open; non-mutating probes only
  "/auth/providers|"
  "/user/login-password|email=nobody%40example.invalid&password=x&remember_me=false"
  "/user/request-password-reset|email=nobody%40example.invalid"
  "/user/verify-email|token=definitely-not-valid"
)

# ---- helpers ----------------------------------------------------------------
# probe PATH BODY [extra curl args...] -> echoes status; body in $BODYFILE.
# Always POST, form-encoded (curl --data defaults to x-www-form-urlencoded).
# Retries through tower_governor 429s so every request reaches its gate.
probe() {
  local path="$1" body="$2"; shift 2
  local code tries=0
  while :; do
    code="$(curl -sS -o "$BODYFILE" -w '%{http_code}' --max-time 10 \
            -X POST "${BASE}${path}" --data "$body" "$@" 2>/dev/null)"
    if [[ "$code" == "429" && "$tries" -lt "$RL_MAX_RETRY" ]]; then
      ((tries++)); sleep "$RL_REFILL"; continue
    fi
    break
  done
  echo "$code"
}

snippet() { tr -d '\n' < "$BODYFILE" | cut -c1-90; }

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
  local entry path body code
  for entry in "$@"; do
    IFS='|' read -r path body <<<"$entry"
    printf '  POST %s\n' "$path"
    code="$(probe "$path" "$body")"
    assert_denied "$code"
  done
}

login_as() { # email jar -> echoes "ok" only if truly authenticated (LoginOutcome==LoggedIn)
  probe /user/register-password "email=$(enc "$1")&password=${NONADMIN_PASS}" >/dev/null
  probe /user/login-password "email=$(enc "$1")&password=${NONADMIN_PASS}&remember_me=false" -c "$2" >/dev/null
  grep -qi 'LoggedIn' "$BODYFILE" && echo ok
}

# ---- preflight --------------------------------------------------------------
command -v curl >/dev/null 2>&1 || { echo "error: curl required." >&2; exit 1; }
pre="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${ROOT}/" 2>/dev/null)"
if [[ -z "$pre" || "$pre" == "000" ]]; then
  echo "error: ${ROOT}/ not responding. Start it: DX_AUTH_SKIP_EMAIL_VERIFICATION=1 cargo leptos serve" >&2
  exit 1
fi
echo "target: ${BASE} (preflight ${pre})"

# Claim the first-admin slot up front: arium grants `admin` to the first signup
# on a fresh DB (auth::maybe_grant_first_admin). Without this, Phase 2's
# "non-admin" would be the bootstrap admin and mask real escalation. Harmless on
# a populated DB. No cookie saved, so Phase 1 stays anonymous.
probe /user/register-password "email=probe-bootstrap-admin%40example.com&password=${NONADMIN_PASS}" >/dev/null

# ---- PHASE 1: anonymous caller must be denied -------------------------------
run_group "PHASE 1a — PROTECTED endpoints, ANONYMOUS (must deny)" "${PROTECTED[@]}"
run_group "PHASE 1b — ADMIN endpoints, ANONYMOUS (must deny)"     "${ADMIN[@]}"

echo; echo "=== PHASE 1c — PUBLIC endpoints reachable (must not 404) ==="
for entry in "${PUBLIC[@]}"; do
  IFS='|' read -r path body <<<"$entry"
  printf '  POST %s\n' "$path"
  code="$(probe "$path" "$body")"
  if [[ "$code" == "404" ]]; then
    echo "    FAIL  [404] not mounted — inventory drift or wrong path"; ((fail++))
  else
    echo "    PASS  [$code] reachable"; ((pass++))
  fi
done

echo; echo "=== PHASE 1d — /api/user/profile must not leak identity to anon ==="
code="$(probe /user/profile "")"
body="$(tr -d '\n' < "$BODYFILE")"
printf '  POST %s\n' "/user/profile"
if grep -qiE '"is_authenticated"[[:space:]]*:[[:space:]]*true|"authenticated"[[:space:]]*:[[:space:]]*true' <<<"$body"; then
  echo "    FAIL  [$code] *** anon got an AUTHENTICATED profile *** — $(snippet)"; ((fail++))
elif [[ "$code" =~ ^2 ]]; then
  echo "    PASS  [$code] anonymous profile (is_authenticated:false)"; ((pass++))
else
  echo "    PASS  [$code] denied — $(snippet)"; ((pass++))
fi

echo; echo "=== PHASE 1e — anon-tolerant endpoints must return a benign default ==="
printf '  POST %s\n' "/user/logout"
code="$(probe /user/logout "")"
body="$(tr -d '\n' < "$BODYFILE")"
if [[ "$code" =~ ^2 ]] && [[ "$body" =~ ^(null|\{\}|)$ ]]; then
  echo "    PASS  [$code] no-op for anon — $(snippet)"; ((pass++))
elif [[ ! "$code" =~ ^2 ]]; then
  echo "    PASS  [$code] denied — $(snippet)"; ((pass++))
else
  echo "    FAIL  [$code] *** logout returned non-empty body to anon *** — $(snippet)"; ((fail++))
fi
printf '  POST %s\n' "/user/mfa/status"
code="$(probe /user/mfa/status "")"
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

# ---- PHASE 2: logged-in non-admin must NOT reach admin endpoints ------------
echo
if [[ -n "$NONADMIN_EMAIL" ]]; then
  echo "=== PHASE 2 — ADMIN endpoints as a LOGGED-IN NON-ADMIN (must refuse) ==="
  if [[ "$(login_as "$NONADMIN_EMAIL" "$JAR")" == ok ]]; then
    echo "  logged in as ${NONADMIN_EMAIL} (cookie captured)"
    for entry in "${ADMIN[@]}"; do
      IFS='|' read -r path body <<<"$entry"
      printf '  POST %s\n' "$path"
      code="$(probe "$path" "$body" -b "$JAR")"
      assert_denied "$code"   # expect "don't have permission"
    done
  else
    echo "  SKIP  could not log in as ${NONADMIN_EMAIL} — set DX_AUTH_SKIP_EMAIL_VERIFICATION=1. (Body: $(snippet))"
  fi
else
  echo "=== PHASE 2 — skipped (set NONADMIN_EMAIL to run the privilege-escalation"
  echo "    check: a non-admin must be refused on /api/admin/*) ==="
fi

# ---- PHASE 3: horizontal isolation (IDOR) -----------------------------------
echo
echo "=== PHASE 3 — horizontal isolation: B must not revoke A's API token (IDOR) ==="
ir="$RANDOM-$$"
IA="probe-idor-a-$ir@example.com"; IB="probe-idor-b-$ir@example.com"
JA="$(mktemp)"; JB="$(mktemp)"
if [[ "$(login_as "$IA" "$JA")" == ok && "$(login_as "$IB" "$JB")" == ok ]]; then
  probe /user/tokens/new "name=idor-probe-victim" -b "$JA" >/dev/null
  tid="$(grep -oE '"id":[0-9]+' "$BODYFILE" | head -1 | grep -oE '[0-9]+')"
  if [[ -z "$tid" ]]; then
    echo "  SKIP  couldn't create/parse A's token (is the 'tokens' feature on?) — $(snippet)"
  else
    printf '  POST %s  (A token_id=%s)\n' "/user/tokens/revoke" "$tid"
    code="$(probe /user/tokens/revoke "token_id=$tid" -b "$JB")"     # B attacks
    bbody="$(tr -d '\n' < "$BODYFILE")"
    ctrl="$(probe /user/tokens/revoke "token_id=$tid" -b "$JA")"     # control: A revokes own
    if [[ "$code" =~ ^2 && "$bbody" =~ ^(null|\{\}|)$ ]]; then
      echo "    FAIL  [$code] *** B REVOKED A'S TOKEN — IDOR *** — $bbody"; ((fail++))
    elif [[ "$ctrl" =~ ^2 ]]; then
      echo "    PASS  [$code] B refused ($(echo "$bbody" | cut -c1-50)); control: A revoked own token [$ctrl]"; ((pass++))
    else
      echo "    WARN  B refused [$code] but control revoke also failed [$ctrl] — inconclusive"; ((fail++))
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
