#!/usr/bin/env bash
#
# Docker PoC sandbox runner.
#
# Runs a candidate exploit inside a hardened Docker container with:
#   - no network
#   - read-only root filesystem
#   - non-root user (nobody)
#   - all capabilities dropped
#   - no new privileges
#   - memory and CPU limits
#   - pid limit
#   - open file limit
#   - a read-only bind mount of only the finding's PoC directory
#   - a 30 second wall clock timeout
#
# Usage:
#   bash .claude/tools/docker_poc.sh <finding_id>
#
# Reads:
#   .claude/output/poc/<finding_id>/exploit.py
#
# Writes:
#   .claude/output/poc/<finding_id>/stdout.txt
#   .claude/output/poc/<finding_id>/stderr.txt
#   .claude/output/poc/<finding_id>/exit_code.txt

set -euo pipefail

FINDING_ID="${1:?usage: docker_poc.sh <finding_id>}"

# Validate FINDING_ID strictly. Unvalidated it flows into POC_DIR, into
# POC_DIR_ABS via pwd, and into the --mount KV string where a traversal or
# a comma injects mount semantics. A single regex kills three 2026-04-23
# findings (FND-PATH-0001, FND-PATH-0007, FND-INJ-0007). See
# docs/superpowers/specs/2026-04-23-bash-guard-rewrite-slice-design.md.
if [[ ! "${FINDING_ID}" =~ ^[A-Z]+-[A-Z]+-[0-9]{4}$ ]]; then
    echo "ERROR: invalid FINDING_ID: must match ^[A-Z]+-[A-Z]+-[0-9]{4}\$. Got: ${FINDING_ID}" >&2
    exit 3
fi

POC_DIR=".claude/output/poc/${FINDING_ID}"
IMAGE="${POC_IMAGE:-adversarial-review-poc:3.12}"

if [[ ! -f "${POC_DIR}/exploit.py" ]]; then
    echo "ERROR: no exploit.py found at ${POC_DIR}/exploit.py" >&2
    exit 1
fi

# Absolute path for the bind mount. Use `pwd -P` to resolve symlinks, then
# verify the physical path is exactly the canonical expected location — a
# symlink at POC_DIR would otherwise bind-mount an attacker-controlled
# directory into the container (FND-PATH-0101).
EXPECTED_POC_PARENT="$(cd .claude/output/poc && pwd -P)"
POC_DIR_ABS="$(cd "${POC_DIR}" && pwd -P)"
EXPECTED_POC_DIR="${EXPECTED_POC_PARENT}/${FINDING_ID}"
if [[ "${POC_DIR_ABS}" != "${EXPECTED_POC_DIR}" ]]; then
    echo "ERROR: POC_DIR resolves outside expected location (symlink escape?): ${POC_DIR_ABS} != ${EXPECTED_POC_DIR}" >&2
    exit 4
fi

# Verify the image exists. If not, we error out; we do NOT auto-build
# because docker build is in the deny list. Build happens at harness
# install time via a separate documented step.
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "ERROR: Docker image ${IMAGE} not found." >&2
    echo "Build it once at install time with: docker build -t ${IMAGE} .claude/tools/poc_image/" >&2
    exit 2
fi

STDOUT_FILE="${POC_DIR}/stdout.txt"
STDERR_FILE="${POC_DIR}/stderr.txt"
EXIT_CODE_FILE="${POC_DIR}/exit_code.txt"

: > "${STDOUT_FILE}"
: > "${STDERR_FILE}"

set +e
docker run \
    --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --user 65534:65534 \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --pids-limit 64 \
    --memory 256m \
    --memory-swap 256m \
    --cpus 1 \
    --ulimit nofile=64:64 \
    --mount "type=bind,source=${POC_DIR_ABS},target=/poc,readonly" \
    "${IMAGE}" \
    timeout 30 python /poc/exploit.py \
    > "${STDOUT_FILE}" 2> "${STDERR_FILE}"
EXIT_CODE=$?
set -e

echo "${EXIT_CODE}" > "${EXIT_CODE_FILE}"

# Summary to stdout for the calling agent to interpret.
echo "=== PoC execution summary for ${FINDING_ID} ==="
echo "Exit code: ${EXIT_CODE}"
echo ""
echo "--- stdout (first 2000 bytes) ---"
head -c 2000 "${STDOUT_FILE}" || true
echo ""
echo "--- stderr (first 2000 bytes) ---"
head -c 2000 "${STDERR_FILE}" || true
echo ""
echo "=== end ${FINDING_ID} ==="

exit 0
