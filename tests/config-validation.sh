#!/usr/bin/env bash
# Config validation: init must refuse malformed environment values.
#
# Every env value is substituted into the UCL config templates under
# /etc/rspamd/local.d/ (a quote or newline would break out of the
# string and smuggle arbitrary extra directives — config injection),
# used as part of a file path (DOMAINS, SELECTOR), or spoken verbatim
# in the SMTP notification dialogue (NOTIFY_*, where a CRLF would
# inject SMTP commands). init therefore whitelist-validates every
# value up front and exits with a clear `invalid <VAR>` error before
# anything else runs.
#
# The image is shell-free, so the checks run from outside: the
# `--healthcheck` entrypoint path performs the same validation first,
# fails fast (no worker is running) and never touches the network —
# `--network none` pins that. `--pull=never` keeps docker from testing
# a stale registry image instead of the local build.
#
# Usage: tests/config-validation.sh IMAGE

set -uo pipefail

IMAGE="${1:-mwaeckerlin/rspamd}"

PASS=0
FAIL=0
declare -a FAILED_NAMES

_pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
_fail() { FAIL=$((FAIL + 1)); FAILED_NAMES+=("$1"); echo "  FAIL  $1: $2"; }

_image_exists() {
    if docker image inspect "${IMAGE}" > /dev/null 2>&1; then
        return 0
    fi
    _fail "image_exists" "image not built — run 'npm run build' first"
    return 1
}

# A malformed value must abort with a message naming the variable.
_reject() {
    local name="$1" var="$2" value="$3"
    local out rc
    out=$(timeout 30 docker run --rm --pull=never --network none \
              -e "${var}=${value}" "${IMAGE}" --healthcheck 2>&1)
    rc=$?
    if [[ ${rc} -ne 0 && "${out}" == *"invalid ${var}"* ]]; then
        _pass "reject_${name}"
    else
        _fail "reject_${name}" "value not rejected (rc=${rc}): ${out}"
    fi
}

# A well-formed value must pass validation (the probe itself fails —
# no worker is running — but no validation error may appear).
_accept() {
    local name="$1"
    shift
    local out
    out=$(timeout 30 docker run --rm --pull=never --network none \
              "$@" "${IMAGE}" --healthcheck 2>&1)
    if [[ "${out}" == *"invalid "* ]]; then
        _fail "accept_${name}" "valid value rejected: ${out}"
    else
        _pass "accept_${name}"
    fi
}

echo "==> Config validation: malformed environment must be refused"

_image_exists || { echo ""; echo "==> Config validation results: 0 passed, 1 failed"; exit 1; }

_reject domain_traversal      DOMAINS               "example.com ../../etc"
_reject selector_traversal    SELECTOR              "mail/../../x"
_reject redis_host_injection  REDIS_HOST            $'redis"\nservers = "evil'
_reject redis_port_bad        REDIS_PORT            "6379x"
_reject clamav_port_range     CLAMAV_PORT           "99999"
_reject reject_score_bad      RSPAMD_REJECT_SCORE   "15; evil = true"
_reject greylist_timeout_bad  RSPAMD_GREYLIST_TIMEOUT "300seconds"
_reject local_addrs_injection RSPAMD_LOCAL_ADDRS    $'10.0.0.0/8";\nsecure_ip = "0.0.0.0/0'
_reject sign_networks_quote   RSPAMD_SIGN_NETWORKS  '127.0.0.0/8", "0.0.0.0/0'
_reject log_level_injection   RSPAMD_LOG_LEVEL      'info"; systemd = true; x = "'
_reject bayes_bad             RSPAMD_BAYES_PER_USER "maybe"
_reject notify_email_crlf     NOTIFY_EMAIL          $'a@b.c\r\nRCPT TO:<x@y.z>'
_reject notify_smtp_bad       NOTIFY_SMTP           "1.2.3.4:25 extra"

_accept defaults
_accept explicit_values \
    -e DOMAINS="example.com example.net" \
    -e SELECTOR=mail2026 \
    -e REDIS_HOST=redis \
    -e REDIS_PORT=6379 \
    -e CLAMAV_HOST=clamav \
    -e CLAMAV_PORT=3310 \
    -e RSPAMD_REJECT_SCORE=15 \
    -e RSPAMD_ADDHEADER_SCORE=5.5 \
    -e RSPAMD_GREYLIST_TIMEOUT=300s \
    -e RSPAMD_GREYLIST_EXPIRE=35d \
    -e RSPAMD_BAYES_PER_USER=false \
    -e RSPAMD_LOG_LEVEL=info \
    -e RSPAMD_LOCAL_ADDRS='192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.0/8, ::1' \
    -e RSPAMD_SIGN_NETWORKS='10.0.0.0/8, 127.0.0.0/8' \
    -e NOTIFY_EMAIL=hostmaster@example.com \
    -e NOTIFY_SMTP=10.0.0.5:25

echo ""
echo "==> Config validation results: ${PASS} passed, ${FAIL} failed"
if [[ ${FAIL} -gt 0 ]]; then
    echo "==> Failed checks: ${FAILED_NAMES[*]}"
    exit 1
fi
