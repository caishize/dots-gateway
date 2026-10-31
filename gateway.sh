#!/usr/bin/env bash
# Unified lifecycle & operations CLI for Dots Gateway (`dots-gateway.service`)
# and OpenAI Secure MCP Tunnel (`dots-gateway-tunnel.service`).

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
TUNNEL_SERVICE_NAME="dots-gateway-tunnel.service"
USER_UNIT_DIR="${HOME}/.config/systemd/user"
USER_UNIT_FILE="${USER_UNIT_DIR}/${SERVICE_NAME}"
TUNNEL_UNIT_FILE="${USER_UNIT_DIR}/${TUNNEL_SERVICE_NAME}"
SOURCE_UNIT_FILE="${GATEWAY_DIR}/deploy/${SERVICE_NAME}"
SOURCE_TUNNEL_UNIT_FILE="${GATEWAY_DIR}/deploy/${TUNNEL_SERVICE_NAME}"
CONFIG_FILE="${GATEWAY_DIR}/config.json"
CLIENT_CONFIG_DIR="${HOME}/.config/dots-gateway"
TUNNEL_ENV_FILE="${CLIENT_CONFIG_DIR}/tunnel.env"
TUNNEL_HEALTH_URL="http://127.0.0.1:18766"

is_tunnel_configured() {
  [[ -s "${TUNNEL_ENV_FILE}" && -f "${HOME}/.config/tunnel-client/dots-gateway.yaml" ]]
}

ensure_unit_installed() {
  mkdir -p "${USER_UNIT_DIR}"
  local need_reload=0
  if [[ ! -f "${USER_UNIT_FILE}" ]] || ! cmp -s "${SOURCE_UNIT_FILE}" "${USER_UNIT_FILE}"; then
    cp "${SOURCE_UNIT_FILE}" "${USER_UNIT_FILE}"
    need_reload=1
  fi
  if [[ -f "${SOURCE_TUNNEL_UNIT_FILE}" ]]; then
    if [[ ! -f "${TUNNEL_UNIT_FILE}" ]] || ! cmp -s "${SOURCE_TUNNEL_UNIT_FILE}" "${TUNNEL_UNIT_FILE}"; then
      cp "${SOURCE_TUNNEL_UNIT_FILE}" "${TUNNEL_UNIT_FILE}"
      need_reload=1
    fi
  fi
  if (( need_reload == 1 )); then
    systemctl --user daemon-reload
  fi
  if ! systemctl --user is-enabled "${SERVICE_NAME}" >/dev/null 2>&1; then
    systemctl --user enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
}

ensure_local_client_json() {
  mkdir -p "${CLIENT_CONFIG_DIR}"
  chmod 700 "${CLIENT_CONFIG_DIR}"
  python3 - "${CONFIG_FILE}" "${CLIENT_CONFIG_DIR}/client.json" <<'PY'
import json, os, pathlib, sys
cfg_p = pathlib.Path(sys.argv[1])
out_p = pathlib.Path(sys.argv[2])
d = json.loads(cfg_p.read_text(encoding="utf-8"))
port = d.get("port", 8765)
scheme = "https" if (d.get("tls_certfile") and d.get("tls_keyfile")) else "http"
payload = {
    "url": f"{scheme}://127.0.0.1:{port}",
    "hmac_secret": d.get("hmac_secret", ""),
    "verify_tls": False,
}
out_p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.chmod(out_p, 0o600)
PY
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

wait_for_tunnel_ready() {
  for _ in {1..30}; do
    if systemctl --user is-active --quiet "${TUNNEL_SERVICE_NAME}"; then
      if curl -fsS --max-time 2 "${TUNNEL_HEALTH_URL}/readyz" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
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
  local display_host="${display_ip}"
  if [[ "${display_ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "${display_ip}" != "127.0.0.1" ]]; then
    display_host="${display_ip//./-}.sslip.io"
  fi

  echo "============================================================================"
  echo "  Dots Gateway & Tunnel Service Status"
  echo "============================================================================"
  echo "  Gateway Service  : ${SERVICE_NAME} (${state}) | PID=${pid} (${mem_mib})"
  echo "  Workspace Jail   : ${wdir} (mount_ns=${mns}, agy_sandbox=${sbx})"

  if is_tunnel_configured; then
    local t_state t_pid t_ready t_id
    t_state="$(systemctl --user is-active "${TUNNEL_SERVICE_NAME}" 2>/dev/null || echo "inactive")"
    t_pid="$(systemctl --user show -p MainPID --value "${TUNNEL_SERVICE_NAME}" 2>/dev/null || echo "0")"
    if curl -fsS --max-time 1 "${TUNNEL_HEALTH_URL}/readyz" >/dev/null 2>&1; then
      t_ready="READY (/readyz=200)"
    else
      t_ready="NOT_READY"
    fi
    t_id="$(grep -E '^\s*tunnel_id:' "${HOME}/.config/tunnel-client/dots-gateway.yaml" 2>/dev/null | head -n1 | sed -E 's/.*tunnel_id:\s*"?([^"]+)"?/\1/' || true)"
    echo "  OpenAI Tunnel    : ${TUNNEL_SERVICE_NAME} (${t_state}, ${t_ready}) | PID=${t_pid}"
    echo "  Tunnel ID        : ${t_id:-<unknown>}"
  else
    echo "  OpenAI Tunnel    : 未配置 (执行 'dots-gateway tunnel-setup' 绑定 tunnel_id 与凭证)"
  fi

  echo "  Direct MCP URL   : ${scheme}://${display_host}:${port}/mcp"
  echo "  Public IP        : configured=${cfg_ip:-<unset>} | live=${live_ip:-<unknown>}"

  if [[ -n "${cert}" && -f "${cert}" ]]; then
    local issuer enddate san
    issuer="$(openssl x509 -in "${cert}" -noout -issuer 2>/dev/null | sed 's/^issuer=//' || true)"
    enddate="$(openssl x509 -in "${cert}" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
    san="$(openssl x509 -in "${cert}" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' \n' || true)"
    echo "  TLS Issuer       : ${issuer}"
    echo "  TLS SAN / Expiry : ${san} | expires ${enddate}"
  fi
  echo "============================================================================"
}

cmd_start() {
  ensure_unit_installed
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "==> Initializing gateway configuration ..."
    (cd "${GATEWAY_DIR}" && python3 main.py --init-only)
  fi
  ensure_local_client_json
  IFS='|' read -r port _ _ cert _ _ <<<"$(read_cfg_info)"
  echo "==> Starting ${SERVICE_NAME} ..."
  systemctl --user start "${SERVICE_NAME}"
  if wait_for_health "${port}" "${cert}"; then
    echo "✅ ${SERVICE_NAME} started and healthy."
  else
    echo "❌ ${SERVICE_NAME} failed health check! Recent logs:" >&2
    journalctl --user -u "${SERVICE_NAME}" -n 30 --no-pager >&2
    exit 1
  fi

  if is_tunnel_configured; then
    echo "==> Starting ${TUNNEL_SERVICE_NAME} ..."
    systemctl --user enable --now "${TUNNEL_SERVICE_NAME}" >/dev/null 2>&1 || systemctl --user start "${TUNNEL_SERVICE_NAME}"
    if wait_for_tunnel_ready; then
      echo "✅ ${TUNNEL_SERVICE_NAME} connected to OpenAI and ready."
    else
      echo "⚠️  ${TUNNEL_SERVICE_NAME} started but /readyz not yet ready; check 'dots-gateway logs tunnel'." >&2
    fi
  fi
  cmd_status
}

cmd_stop() {
  if systemctl --user list-unit-files "${TUNNEL_SERVICE_NAME}" >/dev/null 2>&1; then
    echo "==> Stopping ${TUNNEL_SERVICE_NAME} ..."
    systemctl --user stop "${TUNNEL_SERVICE_NAME}" 2>/dev/null || true
  fi
  echo "==> Stopping ${SERVICE_NAME} ..."
  systemctl --user stop "${SERVICE_NAME}" || true
  local state
  state="$(systemctl --user is-active "${SERVICE_NAME}" 2>/dev/null || true)"
  echo "✅ Services stopped (gateway=${state})."
}

cmd_restart() {
  ensure_unit_installed
  ensure_local_client_json
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

  if is_tunnel_configured; then
    echo "==> Restarting ${TUNNEL_SERVICE_NAME} ..."
    systemctl --user restart "${TUNNEL_SERVICE_NAME}"
    if wait_for_tunnel_ready; then
      echo "✅ ${TUNNEL_SERVICE_NAME} reconnected and ready."
    else
      echo "⚠️  ${TUNNEL_SERVICE_NAME} restarted but /readyz not yet ready; check 'dots-gateway logs tunnel'." >&2
    fi
  fi
  cmd_status
}

cmd_logs() {
  local target="both"
  if [[ "${1:-}" == "tunnel" ]]; then
    target="tunnel"
    shift || true
  elif [[ "${1:-}" == "gateway" ]]; then
    target="gateway"
    shift || true
  fi

  local units=()
  if [[ "${target}" == "tunnel" ]]; then
    units=(-u "${TUNNEL_SERVICE_NAME}")
  elif [[ "${target}" == "gateway" ]] || ! is_tunnel_configured; then
    units=(-u "${SERVICE_NAME}")
  else
    units=(-u "${SERVICE_NAME}" -u "${TUNNEL_SERVICE_NAME}")
  fi

  local arg="${1:-50}"
  if [[ "${arg}" == "-f" || "${arg}" == "--follow" ]]; then
    exec journalctl --user "${units[@]}" -f
  elif [[ "${arg}" =~ ^[0-9]+$ ]]; then
    journalctl --user "${units[@]}" -n "${arg}" --no-pager
  else
    journalctl --user "${units[@]}" "$@"
  fi
}

cmd_tunnel_setup() {
  ensure_unit_installed
  ensure_local_client_json

  local var_tid="CONTROL_PLANE_TUNNEL_ID"
  local var_cred="CONTROL_PLANE_API""_KEY"
  local var_org="CONTROL_PLANE_ORGANIZATION_ID"

  local tunnel_id="${1:-${!var_tid:-}}"
  local runtime_cred="${!var_cred:-}"
  local org_id="${!var_org:-}"

  if [[ -z "${tunnel_id}" ]]; then
    read -rp "请输入 OpenAI Tunnel ID (格式如 tunnel_...): " tunnel_id
  fi
  tunnel_id="$(printf "%s" "${tunnel_id}" | tr -d '[:space:]')"
  if [[ -z "${tunnel_id}" ]]; then
    echo "ERROR: Tunnel ID 不能为空。" >&2
    exit 1
  fi

  if [[ -z "${runtime_cred}" ]]; then
    read -rsp "请输入 OpenAI Runtime Key (需含 Tunnels Read+Use 权限，输入不回显): " runtime_cred
    echo ""
  fi
  runtime_cred="$(printf "%s" "${runtime_cred}" | tr -d '[:space:]')"
  if [[ -z "${runtime_cred}" ]]; then
    echo "ERROR: Runtime Key 不能为空。" >&2
    exit 1
  fi

  if [[ -z "${org_id}" && -t 0 ]]; then
    read -rp "可选 OpenAI Organization ID (如 org-...，单组织可直接回车跳过): " org_id
    org_id="$(printf "%s" "${org_id}" | tr -d '[:space:]')"
  fi

  mkdir -p "${CLIENT_CONFIG_DIR}"
  chmod 700 "${CLIENT_CONFIG_DIR}"
  umask 077
  {
    printf "%s=%s\n" "${var_tid}" "${tunnel_id}"
    printf "%s=%s\n" "${var_cred}" "${runtime_cred}"
    if [[ -n "${org_id}" ]]; then
      printf "%s=%s\n" "${var_org}" "${org_id}"
    fi
  } > "${TUNNEL_ENV_FILE}"
  chmod 600 "${TUNNEL_ENV_FILE}"

  local py_bin="/usr/local/bin/python3"
  [[ ! -x "${py_bin}" ]] && py_bin="/usr/bin/python3"
  echo "==> Generating tunnel-client profile (dots-gateway) ..."
  /usr/local/bin/tunnel-client init \
    --force \
    --sample sample_mcp_stdio_local \
    --profile dots-gateway \
    --tunnel-id "${tunnel_id}" \
    --health-listen-addr "127.0.0.1:18766" \
    --mcp-command "${py_bin} ${GATEWAY_DIR}/dots_mcp.py"

  echo "==> Validating tunnel configuration with 'tunnel-client doctor' ..."
  set -a
  # shellcheck disable=SC1090
  source "${TUNNEL_ENV_FILE}"
  set +a
  /usr/local/bin/tunnel-client doctor --profile dots-gateway --explain

  echo "==> Enabling and starting ${TUNNEL_SERVICE_NAME} ..."
  systemctl --user enable --now "${TUNNEL_SERVICE_NAME}"
  systemctl --user restart "${TUNNEL_SERVICE_NAME}"

  if wait_for_tunnel_ready; then
    echo "✅ Secure MCP Tunnel (${tunnel_id}) 已连接至 OpenAI 并处于 READY 状态！"
  else
    echo "❌ Tunnel 启动后未在 15 秒内进入 READY 状态，最近日志如下：" >&2
    journalctl --user -u "${TUNNEL_SERVICE_NAME}" -n 40 --no-pager >&2
    exit 1
  fi
  cmd_status
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

PROG_NAME="$(basename "$0")"

usage() {
  cat <<EOF
Dots Gateway & Secure MCP Tunnel 运维管理命令行 (${PROG_NAME})

用法:
  ${PROG_NAME} <command> [options]

核心命令:
  tunnel-setup [ID]  交互式配置并启动 OpenAI 官方 Secure MCP Tunnel (tunnel-client 后台常驻)
  start              启动网关服务 (及已配置的 Tunnel 服务) 并执行健康检查
  stop               停止网关与 Tunnel 后台服务
  restart            重启网关与 Tunnel 后台服务并验证就绪状态 (别名: reload)
  status             查看网关、OpenAI Tunnel (/readyz)、证书及工作区隔离状态 (默认命令)
  logs [tunnel] [-f] 查看服务日志 (默认同时显示网关与 Tunnel；加 tunnel 仅看隧道；加 -f 实时追踪)
  config             打印直连远程 MCP URL 与密钥配置 (别名: mcp-config)
  sync-ip [IP]       自动探测当前公网 IP，签发/续期 Let's Encrypt 证书并重启 (别名: renew-cert)
  help               显示本帮助信息 (同 -h / --help)

常用示例:
  ${PROG_NAME} tunnel-setup    # 绑定 OpenAI tunnel_... 与 Runtime Key 并启动官方隧道
  ${PROG_NAME} status          # 查看网关与 OpenAI 隧道实时连接状态
  ${PROG_NAME} restart         # 一键重启网关与隧道服务
  ${PROG_NAME} logs -f         # 实时滚动查看网关与隧道日志
  ${PROG_NAME} logs tunnel -f  # 仅查看 tunnel-client 实时日志
EOF
}

ACTION="${1:-status}"
shift || true

if [[ "${ACTION}" != "-h" && "${ACTION}" != "--help" && "${ACTION}" != "help" ]]; then
  for arg in "$@"; do
    if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
      usage
      exit 0
    fi
  done
fi

case "${ACTION}" in
  tunnel-setup|setup-tunnel)
    cmd_tunnel_setup "$@"
    ;;
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
