#!/usr/bin/env bash
# Environment contract: every operator setting reaches the effective
# rspamd configuration — the image default when the variable is unset,
# the operator's value when it is set.
#
# Each case starts the image with its environment and waits until init
# has staged /etc/rspamd/local.d and both workers listen (the
# --healthcheck probe answers), so rspamd has loaded the staged files.
# The test then reads the staged file and lets `rspamadm configtest`
# parse the whole configuration inside the running container.
# `--network none` keeps the container off every network, and the
# upstream names resolve to loopback through /etc/hosts (see HOSTS);
# `--pull=never` tests the local build.
#
# Usage: tests/env-config.sh IMAGE

set -uo pipefail

IMAGE="${1:-mwaeckerlin/rspamd}"

PASS=0
FAIL=0
declare -a FAILED_NAMES
declare -a CONTAINERS

_pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
_fail() { FAIL=$((FAIL + 1)); FAILED_NAMES+=("$1"); echo "  FAIL  $1: $2"; }

_cleanup() {
    [[ ${#CONTAINERS[@]} -gt 0 ]] && docker rm -f "${CONTAINERS[@]}" > /dev/null 2>&1
}
trap _cleanup EXIT

_image_exists() {
    if docker image inspect "${IMAGE}" > /dev/null 2>&1; then
        return 0
    fi
    _fail "image_exists" "image not built — run 'npm run build' first"
    return 1
}

# Start the image with the given docker arguments; sets CID once both
# workers answer, fails after 60 probes.
_start() {
    local name="$1" i
    shift
    CID=$(docker run -d --pull=never --network none -e DOMAIN=example.com \
              "${HOSTS[@]}" "$@" "${IMAGE}")
    CONTAINERS+=("${CID}")
    for i in $(seq 1 60); do
        if docker exec "${CID}" /usr/bin/init --healthcheck > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    _fail "${name}_started" "workers never came up: $(docker logs "${CID}" 2>&1)"
    return 1
}

# Without a resolver each upstream lookup at config load fails only after ~5 s.
HOSTS=(--add-host redis:127.0.0.1 --add-host clamav:127.0.0.1
       --add-host fuzzy1.rspamd.com:127.0.0.1 --add-host fuzzy2.rspamd.com:127.0.0.1)

_staged() {
    docker cp "${CID}:/etc/rspamd/local.d/$1" - 2>/dev/null | tar -xO 2>/dev/null
}

# The staged file holds the exact line.
_expect_line() {
    local name="$1" file="$2" want="$3"
    if _staged "${file}" | grep -qxF "${want}"; then
        _pass "${name}"
    else
        _fail "${name}" "no line '${want}' in local.d/${file}: $(_staged "${file}")"
    fi
}

# The staged file holds no line matching the extended regular expression.
_expect_no_line() {
    local name="$1" file="$2" pattern="$3" content
    content=$(_staged "${file}")
    if [[ -n "${content}" ]] && ! grep -qE "${pattern}" <<< "${content}"; then
        _pass "${name}"
    else
        _fail "${name}" "line /${pattern}/ present or local.d/${file} missing: ${content}"
    fi
}

_expect_configtest() {
    local name="$1" out
    if out=$(docker exec "${CID}" /usr/bin/rspamadm configtest 2>&1); then
        _pass "${name}"
    else
        _fail "${name}" "rspamadm configtest: ${out}"
    fi
}

echo "==> Environment contract: settings reach the effective configuration"

_image_exists || { echo ""; echo "==> Environment contract results: 0 passed, 1 failed"; exit 1; }

if _start defaults; then
    _expect_line    default_secure_ip   worker-controller.inc \
        'secure_ip = ["127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];'
    _expect_no_line default_no_password worker-controller.inc '^[[:space:]]*password'
    _expect_line    default_proxy_workers worker-proxy.inc 'count = 4;'
    _expect_line    default_min_learns  classifier-bayes.conf 'min_learns = 200;'
    _expect_line    default_max_message options.inc 'max_message = 50Mb;'
    _expect_configtest default_configtest
fi

if _start override \
       -e RSPAMD_CONTROLLER_SECURE_IP="127.0.0.0/8, 10.99.0.0/16" \
       -e RSPAMD_CONTROLLER_PASSWORD='s3cret-Pw' \
       -e RSPAMD_PROXY_WORKERS=7 \
       -e RSPAMD_BAYES_MIN_LEARNS=333 \
       -e RSPAMD_MAX_MESSAGE=77Mb; then
    _expect_line override_secure_ip   worker-controller.inc 'secure_ip = ["127.0.0.0/8", "10.99.0.0/16"];'
    _expect_line override_password    worker-controller.inc 'password = "s3cret-Pw";'
    _expect_line override_proxy_workers worker-proxy.inc 'count = 7;'
    _expect_line override_min_learns  classifier-bayes.conf 'min_learns = 333;'
    _expect_line override_max_message options.inc 'max_message = 77Mb;'
    _expect_configtest override_configtest
fi

echo ""
echo "==> Environment contract results: ${PASS} passed, ${FAIL} failed"
if [[ ${FAIL} -gt 0 ]]; then
    echo "==> Failed checks: ${FAILED_NAMES[*]}"
    exit 1
fi
