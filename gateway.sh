#!/usr/bin/env bash
# Unified lifecycle & operations CLI for Dots Gateway (`dots-gateway.service`).
#
# Usage:
#   ./gateway.sh start          Start background service & verify health
#   ./gateway.sh stop           Stop background service
#   ./gateway.sh restart        Restart background service & verify health
#   ./gateway.sh status         Show service, port, TLS cert, renewal timer & workspace status
#   ./gateway.sh logs [-f|N]    View service logs (-f to follow live, N for line count)
#   ./gateway.sh config         Print ready-to-copy Remote MCP URL & Bearer Token config
#   ./gateway.sh sync-ip [IP]   Detect current public IP, issue/renew Let's Encrypt IP cert & restart

set -euo pipefail

# Resolve real gateway directory even when invoked via ~/.local/bin/dots-gateway symlink
SOURCE="${BASH_SOURCE[0]}"
while [[ -L "${SOURCE}" ]]; do
  LINK_DIR="$(cd -P "$(dirname "${SOURCE}")" && pwd)"
  SOURCE="$(readlink "${SOURCE}")"
  [[ "${SOURCE}" != /* ]] && SOURCE="${LINK_DIR}/${SOURCE}"
done
GATEWAY_DIR="$(cd -P "$(dirname "${SOURCE}")" && pwd)"

SERVICE_NAME="dots-gateway.service"
USER_UNIT_DIR="${HOME}/.config/systemd/user"
USER_UNIT_FILE="${USER_UNIT_DIR}/${SERVICE_NAME}"
SOURCE_UNIT_FILE="${GATEWAY_DIR}/deploy/${SERVICE_NAME}"
CONFIG_FILE="${GATEWAY_DIR}/config.json"

ensure_unit_installed() {
  mkdir -p "${USER_UNIT_DIR}"
  if [[ ! -f "${USER_UNIT_FILE}" ]] || ! cmp -s "${SOURCE_UNIT_FILE}" "${USER_UNIT_FILE}"; then
    cp "${SOURCE_UNIT_FILE}" "${USER_UNIT_FILE}"
    systemctl --user daemon-reload
  fi
  if ! systemctl --user is-enabled "${SERVICE_NAME}" >/dev/null 2>&1; then
    systemctl --user enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
}

detect_public_ip() {
  local ip=""
  ip="$(curl -fsSL --max-time 2 -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(curl -4 -fsSL --max-time 3 https://api.ipify.org 2>/dev/null || true)"
  fi
  printf "%s" "${ip}"
}

read_cfg_info() {
  python3 - "${CONFIG_FILE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
if not p.exists():
    print("8765||/home/<your-user>/workspaces||True|True")
    raise SystemExit(0)
d = json.loads(p.read_text(encoding="utf-8"))
port = d.get("port", 8765)
pub = d.get("public_ip") or ""
wdir = d.get("default_workdir") or ""
cert = d.get("tls_certfile") or ""
mns = d.get("isolate_mount_namespace", True)
sbx = d.get("agy_default_sandbox", True)
print(f"{port}|{pub}|{wdir}|{cert}|{mns}|{sbx}")
PY
}

wait_for_health() {
  local port="$1"
  local cert="$2"
  local scheme="http"
  [[ -n "${cert}" ]] && scheme="https"
  local url="${scheme}://127.0.0.1:${port}/v1/health"

  for _ in {1..20}; do
    if systemctl --user is-active --quiet "${SERVICE_NAME}"; then
      if curl -ksf --max-time 2 "${url}" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
}

check_ip_drift_notice() {
  local cfg_ip="$1"
  local live_ip
  live_ip="$(detect_public_ip)"
  if [[ -n "${live_ip}" && -n "${cfg_ip}" && "${live_ip}" != "${cfg_ip}" ]]; then
    echo "⚠️  注意: 当前机器实时公网 IP (${live_ip}) 与配置中的 IP (${cfg_ip}) 不一致！"
    echo "   如需切换公网 IP 并重签 Let's Encrypt 证书，请执行: ./gateway.sh sync-ip"
  fi
}

cmd_status() {
  IFS='|' read -r port cfg_ip wdir cert mns sbx <<<"$(read_cfg_info)"
  local live_ip
  live_ip="$(detect_public_ip)"
  local state
  state="$(systemctl --user is-active "${SERVICE_NAME}" 2>/dev/null || true)"
  local pid mem
  pid="$(systemctl --user show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || echo "0")"
  mem="$(systemctl --user show -p MemoryCurrent --value "${SERVICE_NAME}" 2>/dev/null || echo "0")"
  local mem_mib="N/A"
  if [[ "${mem}" =~ ^[0-9]+$ ]] && (( mem > 0 )); then
    mem_mib="$(( mem / 1024 / 1024 )) MiB"
  fi

  local scheme="http"
  [[ -n "${cert}" ]] && scheme="https"
  local display_ip="${cfg_ip:-${live_ip:-127.0.0.1}}"

  echo "============================================================================"
  echo "  Dots Gateway Service Status"
  echo "============================================================================"
  echo "  Service Unit     : ${SERVICE_NAME} (${state})"
  echo "  Main PID / RAM   : ${pid} (${mem_mib})"
  echo "  Remote MCP URL   : ${scheme}://${display_ip}:${port}/mcp"
  echo "  Public IP        : configured=${cfg_ip:-<unset>} | live=${live_ip:-<unknown>}"
  echo "  Workspace Jail   : ${wdir} (mount_ns=${mns}, agy_sandbox=${sbx})"

  if [[ -n "${cert}" && -f "${cert}" ]]; then
    local issuer enddate san
    issuer="$(openssl x509 -in "${cert}" -noout -issuer 2>/dev/null | sed 's/^issuer=//' || true)"
    enddate="$(openssl x509 -in "${cert}" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
    san="$(openssl x509 -in "${cert}" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' \n' || true)"
    echo "  TLS Certificate  : ${cert}"
    echo "  TLS Issuer       : ${issuer}"
    echo "  TLS SAN / Expiry : ${san} | expires ${enddate}"
  else
    echo "  TLS Certificate  : DISABLED / NOT FOUND"
  fi

  if systemctl list-unit-files dots-gateway-acme-renew.timer >/dev/null 2>&1; then
    local timer_state
    timer_state="$(systemctl is-active dots-gateway-acme-renew.timer 2>/dev/null || echo "inactive")"
    echo "  ACME Auto-Renew  : dots-gateway-acme-renew.timer (${timer_state})"
  fi
  echo "============================================================================"
  check_ip_drift_notice "${cfg_ip}"
}

cmd_start() {
  ensure_unit_installed
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "==> Initializing gateway configuration ..."
    (cd "${GATEWAY_DIR}" && python3 main.py --init-only)
  fi
  IFS='|' read -r port cfg_ip _ cert _ _ <<<"$(read_cfg_info)"
  echo "==> Starting ${SERVICE_NAME} ..."
  systemctl --user start "${SERVICE_NAME}"
  if wait_for_health "${port}" "${cert}"; then
    echo "✅ ${SERVICE_NAME} started and healthy."
  else
    echo "❌ ${SERVICE_NAME} failed health check! Recent logs:" >&2
    journalctl --user -u "${SERVICE_NAME}" -n 30 --no-pager >&2
    exit 1
  fi
  cmd_status
}

cmd_stop() {
  echo "==> Stopping ${SERVICE_NAME} ..."
  systemctl --user stop "${SERVICE_NAME}" || true
  local state
  state="$(systemctl --user is-active "${SERVICE_NAME}" 2>/dev/null || true)"
  echo "✅ ${SERVICE_NAME} stopped (state=${state})."
}

cmd_restart() {
  ensure_unit_installed
  IFS='|' read -r port _ _ cert _ _ <<<"$(read_cfg_info)"
  echo "==> Restarting ${SERVICE_NAME} ..."
  systemctl --user restart "${SERVICE_NAME}"
  if wait_for_health "${port}" "${cert}"; then
    echo "✅ ${SERVICE_NAME} restarted and healthy."
  else
    echo "❌ ${SERVICE_NAME} failed health check after restart! Recent logs:" >&2
    journalctl --user -u "${SERVICE_NAME}" -n 30 --no-pager >&2
    exit 1
  fi
  cmd_status
}

cmd_logs() {
  local arg="${1:-50}"
  if [[ "${arg}" == "-f" || "${arg}" == "--follow" ]]; then
    exec journalctl --user -u "${SERVICE_NAME}" -f
  elif [[ "${arg}" =~ ^[0-9]+$ ]]; then
    journalctl --user -u "${SERVICE_NAME}" -n "${arg}" --no-pager
  else
    journalctl --user -u "${SERVICE_NAME}" "$@"
  fi
}

cmd_config() {
  (cd "${GATEWAY_DIR}" && python3 main.py --print-plugin-config)
}

cmd_sync_ip() {
  local target_ip="${1:-}"
  if [[ -z "${target_ip}" ]]; then
    target_ip="$(detect_public_ip)"
  fi
  if [[ -z "${target_ip}" ]]; then
    echo "ERROR: Could not auto-detect public IP. Pass explicitly: ./gateway.sh sync-ip <PUBLIC_IP>" >&2
    exit 1
  fi
  echo "==> Syncing gateway public IP & Let's Encrypt certificate for ${target_ip} ..."
  "${GATEWAY_DIR}/deploy/issue_letsencrypt_ip.sh" "${target_ip}"
  cmd_status
}

usage() {
  cat <<'EOF'
Usage: ./gateway.sh <command> [options]

Commands:
  start            Start dots-gateway.service and verify /v1/health
  stop             Stop dots-gateway.service
  restart          Restart dots-gateway.service and verify /v1/health
  status           Display service, port, public IP, TLS cert & workspace jail status
  logs [-f | N]    Show recent logs (default 50 lines) or follow live with -f
  config           Print Remote MCP endpoint URL & Bearer Token configuration
  sync-ip [IP]     Auto-detect public IP, issue/renew Let's Encrypt IP cert & restart
EOF
}

ACTION="${1:-status}"
shift || true

case "${ACTION}" in
  start)
    cmd_start
    ;;
  stop)
    cmd_stop
    ;;
  restart|reload)
    cmd_restart
    ;;
  status)
    cmd_status
    ;;
  logs|log)
    cmd_logs "$@"
    ;;
  config|mcp-config)
    cmd_config
    ;;
  sync-ip|issue-cert|renew-cert)
    cmd_sync_ip "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "Unknown command: ${ACTION}" >&2
    usage >&2
    exit 1
    ;;
esac
