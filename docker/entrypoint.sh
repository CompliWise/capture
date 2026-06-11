#!/usr/bin/env bash
set -euo pipefail

AGENT_ENV_FILE="/etc/compliwise/agent.env"
mkdir -p /etc/compliwise
chmod 755 /etc/compliwise

load_env_file_without_overriding_process_env() {
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ -z "$key" ]] && continue
    if [[ -z "${!key:-}" ]]; then
      export "${key}=${value}"
    fi
  done < "${AGENT_ENV_FILE}"
}

persist_agent_env_from_process_env() {
  local token="${COMPLIWISE_AGENT_TOKEN:-}"
  [[ -n "$token" ]] || return 0

  {
    echo "COMPLIWISE_API_URL=${COMPLIWISE_API_URL:-http://host.docker.internal:4000}"
    echo "COMPLIWISE_ORG_ID=${COMPLIWISE_ORG_ID:-}"
    echo "COMPLIWISE_AGENT_ID=${COMPLIWISE_AGENT_ID:-}"
    echo "COMPLIWISE_AGENT_TOKEN=${token}"
    echo "COMPLIWISE_POLL_INTERVAL=${COMPLIWISE_POLL_INTERVAL:-30}"
    echo "COMPLIWISE_HEARTBEAT_INTERVAL=${COMPLIWISE_HEARTBEAT_INTERVAL:-60}"
  } > "${AGENT_ENV_FILE}"
  chmod 644 "${AGENT_ENV_FILE}"
}

if [[ -n "${COMPLIWISE_ENROLLMENT_CODE:-}" ]] && [[ ! -f "${AGENT_ENV_FILE}" ]]; then
  {
    echo "COMPLIWISE_ENROLLMENT_CODE=${COMPLIWISE_ENROLLMENT_CODE}"
    echo "COMPLIWISE_API_URL=${COMPLIWISE_API_URL:-http://host.docker.internal:4000}"
    echo "COMPLIWISE_ORG_ID=${COMPLIWISE_ORG_ID:-}"
    echo "COMPLIWISE_AGENT_ID=${COMPLIWISE_AGENT_ID:-}"
    echo "COMPLIWISE_AGENT_TOKEN=${COMPLIWISE_AGENT_TOKEN:-}"
    echo "COMPLIWISE_POLL_INTERVAL=${COMPLIWISE_POLL_INTERVAL:-30}"
    echo "COMPLIWISE_HEARTBEAT_INTERVAL=${COMPLIWISE_HEARTBEAT_INTERVAL:-60}"
  } > "${AGENT_ENV_FILE}"
  chmod 644 "${AGENT_ENV_FILE}"
fi

if [[ -f "${AGENT_ENV_FILE}" ]]; then
  chmod 644 "${AGENT_ENV_FILE}"
  load_env_file_without_overriding_process_env
fi

persist_agent_env_from_process_env

export API_SECRET="${API_SECRET:-local-admin-secret}"
export PORT="${PORT:-59232}"
export GIN_MODE="${GIN_MODE:-release}"

exec /usr/bin/capture
