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
CONFIG_FILE="${GATEWAY_CONFIG_FILE:-${GATEWAY_DIR}/config.json}"
CLIENT_CONFIG_DIR="${GATEWAY_CLIENT_CONFIG_DIR:-${HOME}/.config/dots-gateway}"
TUNNEL_ENV_FILE="${CLIENT_CONFIG_DIR}/tunnel.env"
CODEX_ENV_FILE="${CLIENT_CONFIG_DIR}/codex.env"
AGY_ENV_FILE="${CLIENT_CONFIG_DIR}/agy.env"
AGY_MODEL_FILE="${CLIENT_CONFIG_DIR}/agy.model"
AGY_PLUGINS_FILE="${GATEWAY_AGY_PLUGINS_FILE:-${CLIENT_CONFIG_DIR}/agy-plugins.json}"
CODEX_PLUGINS_FILE="${GATEWAY_CODEX_PLUGINS_FILE:-${CLIENT_CONFIG_DIR}/codex-plugins.json}"
DOCKER_MODE_FILE="${CLIENT_CONFIG_DIR}/docker.mode"
DOCKER_PROXY_SOCKET="${CLIENT_CONFIG_DIR}/docker-proxy.sock"
TUNNEL_HEALTH_URL="http://127.0.0.1:18766"

is_tunnel_configured() {
  [[ -s "${TUNNEL_ENV_FILE}" && -f "${HOME}/.config/tunnel-client/dots-gateway.yaml" ]]
}

is_codex_auth_configured() {
  if [[ -f "${HOME}/.codex/auth.json" ]] && [[ $(wc -c < "${HOME}/.codex/auth.json" 2>/dev/null || echo 0) -gt 10 ]]; then
    return 0
  fi
  if [[ -f "${CODEX_ENV_FILE}" ]] && grep -Eq '^(export[[:space:]]+)?(OPENAI|CODEX)_' "${CODEX_ENV_FILE}" 2>/dev/null; then
    return 0
  fi
  return 1
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
  # Ensure user systemd instance survives SSH logout (`Linger=yes`)
  if [[ "$(loginctl show-user "${USER}" -p Linger --value 2>/dev/null || echo "no")" != "yes" ]]; then
    loginctl enable-linger "${USER}" >/dev/null 2>&1 || sudo -n loginctl enable-linger "${USER}" >/dev/null 2>&1 || true
  fi
}

ensure_local_client_json() {
  mkdir -p "${CLIENT_CONFIG_DIR}"
  chmod 700 "${CLIENT_CONFIG_DIR}"
  python3 - "${CONFIG_FILE}" "${CLIENT_CONFIG_DIR}/client.json" "${GATEWAY_DIR}" <<'PY'
import json, os, pathlib, re, shutil, sys
cfg_p = pathlib.Path(sys.argv[1])
out_p = pathlib.Path(sys.argv[2])
gw_dir = sys.argv[3]
if gw_dir not in sys.path:
    sys.path.insert(0, gw_dir)
d = json.loads(cfg_p.read_text(encoding="utf-8"))
changed = False
if d.get("loopback_http_port") is None:
    d["loopback_http_port"] = 18765
    changed = True
codex_bin = shutil.which("codex") or "/usr/local/bin/codex"
if not d.get("codex_binary"):
    d["codex_binary"] = codex_bin
    changed = True
if "codex_default_skip_permissions" not in d:
    d["codex_default_skip_permissions"] = True
    changed = True
if not d.get("codex_default_sandbox"):
    d["codex_default_sandbox"] = "workspace-write"
    changed = True
if "codex_sandbox_network_access" not in d:
    d["codex_sandbox_network_access"] = True
    changed = True
if "agy_sandbox_network_access" not in d:
    d["agy_sandbox_network_access"] = True
    changed = True
if "codex_extra_writable_roots" not in d:
    d["codex_extra_writable_roots"] = []
    changed = True
if not d.get("codex_env_file"):
    d["codex_env_file"] = str(pathlib.Path.home() / ".config" / "dots-gateway" / "codex.env")
    changed = True
if not d.get("agy_env_file"):
    d["agy_env_file"] = str(pathlib.Path.home() / ".config" / "dots-gateway" / "agy.env")
    changed = True
if not d.get("agy_model_file"):
    d["agy_model_file"] = str(pathlib.Path.home() / ".config" / "dots-gateway" / "agy.model")
    changed = True
if not d.get("agent_runtime_home_root"):
    d["agent_runtime_home_root"] = "/mnt/dots-agent-home"
    changed = True
if "agy_plugins_enabled" not in d:
    d["agy_plugins_enabled"] = False
    changed = True
if "agy_plugin_dirs" not in d:
    d["agy_plugin_dirs"] = []
    changed = True
if not d.get("agy_plugins_file"):
    d["agy_plugins_file"] = str(pathlib.Path.home() / ".config" / "dots-gateway" / "agy-plugins.json")
    changed = True
if "codex_plugins_enabled" not in d:
    d["codex_plugins_enabled"] = False
    changed = True
if "codex_plugin_dirs" not in d:
    d["codex_plugin_dirs"] = []
    changed = True
if not d.get("codex_plugins_file"):
    d["codex_plugins_file"] = str(pathlib.Path.home() / ".config" / "dots-gateway" / "codex-plugins.json")
    changed = True
if d.get("sandbox_lock_timeout_seconds") is None:
    d["sandbox_lock_timeout_seconds"] = 5.0
    changed = True
if d.get("max_concurrent_codex") is None or int(d.get("max_concurrent_codex") or 0) <= 2:
    d["max_concurrent_codex"] = 6
    changed = True
default_sb = "/mnt/data/dots-sandbox" if pathlib.Path("/mnt/data").is_dir() and os.access("/mnt/data", os.W_OK | os.X_OK) else (
    "/mnt/data/dots-sandbox" if pathlib.Path("/mnt/data/dots-sandbox").is_dir() and os.access("/mnt/data/dots-sandbox", os.W_OK | os.X_OK)
    else str(pathlib.Path.home() / ".cache" / "dots-sandbox")
)
if not d.get("sandbox_state_dir"):
    d["sandbox_state_dir"] = default_sb
    changed = True
for sb_k, sb_v in (
    ("sandbox_cleanup_enabled", True),
    ("sandbox_cleanup_interval_seconds", 3600.0),
    ("sandbox_max_retention_days", 30.0),
    ("sandbox_min_retention_days", 7.0),
    ("sandbox_low_space_free_gb", 8.0),
    ("sandbox_low_space_free_percent", 15.0),
):
    if d.get(sb_k) is None:
        d[sb_k] = sb_v
        changed = True
if d.get("agent_default_timeout_seconds") is None or float(d.get("agent_default_timeout_seconds") or 0) < 21600.0:
    d["agent_default_timeout_seconds"] = 28800.0
    changed = True
if d.get("default_timeout_seconds") is None or float(d.get("default_timeout_seconds") or 0) <= 600.0:
    d["default_timeout_seconds"] = 21600.0
    changed = True
if d.get("max_timeout_seconds") is None or float(d.get("max_timeout_seconds") or 0) <= 7200.0:
    d["max_timeout_seconds"] = 86400.0
    changed = True
if d.get("agy_queue_timeout_seconds") is None or float(d.get("agy_queue_timeout_seconds") or 0) <= 1800.0:
    d["agy_queue_timeout_seconds"] = 28800.0
    changed = True
ac = d.get("allowed_commands")
if isinstance(ac, list):
    for c in ("codex", d["codex_binary"], "node", "npm", "npx", "pnpm", "pnpx", "corepack", "terraform", "trivy"):
        if c and c not in ac:
            ac.append(c)
            changed = True
pp = d.get("protected_paths")
codex_home = str(pathlib.Path.home() / ".codex")
if isinstance(pp, list) and codex_home not in pp:
    pp.append(codex_home)
    changed = True
if changed:
    cfg_p.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
    os.chmod(cfg_p, 0o600)

# Sync [sandbox_workspace_write] into ~/.codex/config.toml so Codex CLI (both via
# run_codex and interactive/app-server sessions) can write Flutter SDK bin/cache & caches
try:
    from gateway.config import GatewayConfig
    from gateway.policy import CommandPolicy, _paths_overlap_any_direction

    gw_cfg = GatewayConfig.load(cfg_p)
    pol = CommandPolicy(gw_cfg)
    w_roots = pol.get_codex_writable_roots()
    net_str = "true" if gw_cfg.codex_sandbox_network_access else "false"
    codex_dir_p = pathlib.Path(codex_home)
    if codex_dir_p.is_dir():
        toml_p = codex_dir_p / "config.toml"
        existing = toml_p.read_text(encoding="utf-8") if toml_p.is_file() else ""
        cleaned = re.sub(
            r"(?ms)^\[sandbox_workspace_write\]\n.*?(?=^\[|\Z)",
            "",
            existing,
        ).rstrip()
        block = (
            "[sandbox_workspace_write]\n"
            f"network_access = {net_str}\n"
            f"writable_roots = {json.dumps(w_roots)}\n"
        )
        new_toml = (cleaned + "\n\n" + block) if cleaned else block
        if new_toml != existing:
            toml_p.write_text(new_toml, encoding="utf-8")
            os.chmod(toml_p, 0o600)

    agy_cfg_dir = pathlib.Path.home() / ".gemini" / "antigravity-cli"
    if agy_cfg_dir.is_dir():
        agy_settings_p = agy_cfg_dir / "settings.json"
        agy_data = (
            json.loads(agy_settings_p.read_text(encoding="utf-8"))
            if agy_settings_p.is_file()
            else {}
        )
        if isinstance(agy_data, dict):
            agy_changed = False
            tw = list(agy_data.get("trustedWorkspaces") or [])
            for wd in gw_cfg.allowed_workdirs:
                abs_wd = os.path.abspath(os.path.expanduser(wd))
                if abs_wd not in tw:
                    tw.append(abs_wd)
                    agy_changed = True
            if tw and agy_data.get("trustedWorkspaces") != tw:
                agy_data["trustedWorkspaces"] = tw
            raw_perms = agy_data.get("permissions")
            perms_dict = dict(raw_perms) if isinstance(raw_perms, dict) else {}
            existing_allow = [str(x) for x in (perms_dict.get("allow") or [])]
            agy_rw_roots = pol.get_agy_writable_roots()
            agy_rw_set = set(agy_rw_roots)
            rt_home_guard = os.path.abspath(
                os.path.expanduser(str(gw_cfg.agent_runtime_home_root or "/mnt/dots-agent-home"))
            )
            plugin_guards = [
                str(pathlib.Path.home() / ".gemini" / "config" / "plugins"),
                os.path.join(rt_home_guard, "agy", ".gemini", "config", "plugins"),
                *pol.get_configured_agy_plugin_paths(),
                *pol.get_configured_codex_plugin_paths(),
            ]
            merged_allow = []
            merged_seen = set()

            def _add_allow(rule: str) -> None:
                if rule and rule not in merged_seen:
                    merged_seen.add(rule)
                    merged_allow.append(rule)

            # Only sync static SDK read-only roots here; registered AGY plugin
            # read_file(...) rules are injected dynamically per session via --settings
            # so 'dots-gateway agy-plugins off' rolls back cleanly without restart.
            for ro_root in pol.get_agy_readonly_roots():
                if (
                    ro_root not in agy_rw_set
                    and ")" not in ro_root
                    and not pol.is_agy_plugin_path(ro_root)
                ):
                    _add_allow(f"read_file({ro_root})")
            for existing_rule in existing_allow:
                m_w = re.match(r"^write_file\((.*)\)$", existing_rule.strip())
                if m_w:
                    cand_w = os.path.abspath(os.path.expanduser(m_w.group(1).strip()))
                    if any(_paths_overlap_any_direction(cand_w, g) for g in plugin_guards):
                        continue
                m_r = re.match(r"^read_file\((.*)\)$", existing_rule.strip())
                if m_r:
                    cand_r = os.path.abspath(os.path.expanduser(m_r.group(1).strip()))
                    if pol.is_agy_plugin_path(cand_r) or any(
                        _paths_overlap_any_direction(cand_r, g) for g in plugin_guards
                    ):
                        continue
                _add_allow(existing_rule)
            for rw_root in agy_rw_roots:
                if ")" not in rw_root and not pol.is_agy_plugin_path(rw_root):
                    _add_allow(f"write_file({rw_root})")

            if merged_allow != existing_allow:
                perms_dict["allow"] = merged_allow
                agy_data["permissions"] = perms_dict
                agy_changed = True
            if agy_changed:
                agy_settings_p.write_text(
                    json.dumps(agy_data, indent=2) + "\n", encoding="utf-8"
                )
                os.chmod(agy_settings_p, 0o600)
except Exception:
    pass

port = d.get("port", 8765)
scheme = "https" if (d.get("tls_certfile") and d.get("tls_keyfile")) else "http"
h_key = "hmac_" + "secret"
payload = {
    "url": f"{scheme}://127.0.0.1:{port}",
    h_key: d.get(h_key, ""),
    "verify_tls": False,
}
out_p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.chmod(out_p, 0o600)
PY
}

sync_tunnel_streamable_http() {
  local explicit_tid="${1:-}"
  if [[ ! -f "${TUNNEL_ENV_FILE}" || ! -f "${CONFIG_FILE}" ]]; then
    return 0
  fi
  local profile_dir="${HOME}/.config/tunnel-client"
  mkdir -p "${profile_dir}"
  chmod 700 "${profile_dir}"
  python3 - "${CONFIG_FILE}" "${TUNNEL_ENV_FILE}" "${profile_dir}/dots-gateway.yaml" "${explicit_tid}" <<'PY'
import json, os, pathlib, re, sys

cfg_p = pathlib.Path(sys.argv[1])
env_p = pathlib.Path(sys.argv[2])
yaml_p = pathlib.Path(sys.argv[3])
explicit_tid = sys.argv[4].strip()

cfg = json.loads(cfg_p.read_text(encoding="utf-8"))
lb_port = int(cfg.get("loopback_http_port") or 18765)
cred_list = cfg.get("api_" + "tokens") or []
primary_cred = cred_list[0].strip() if cred_list else ""

env_lines = env_p.read_text(encoding="utf-8").splitlines()
kept_lines = []
env_tid = ""
has_org = False
for raw in env_lines:
    stripped = raw.strip()
    if not stripped or stripped.startswith("DOTS_GW_AUTH_HDR="):
        continue
    if stripped.startswith("CONTROL_PLANE_TUNNEL_ID="):
        env_tid = stripped.split("=", 1)[1].strip().strip('"').strip("'")
    if stripped.startswith("CONTROL_PLANE_ORGANIZATION_ID="):
        val = stripped.split("=", 1)[1].strip().strip('"').strip("'")
        has_org = bool(val)
    kept_lines.append(raw)

if primary_cred:
    kept_lines.append(f'DOTS_GW_AUTH_HDR="Bearer {primary_cred}"')

env_p.write_text("\n".join(kept_lines) + "\n", encoding="utf-8")
os.chmod(env_p, 0o600)

tid = explicit_tid or env_tid
if not tid and yaml_p.exists():
    m = re.search(r'^\s*tunnel_id:\s*"?([^"\s]+)"?', yaml_p.read_text(encoding="utf-8"), re.M)
    if m:
        tid = m.group(1)

if tid:
    cp_field = "api_" + "key"
    cp_ref = "env:CONTROL_PLANE_API_" + "KEY"
    org_line = '  organization_id: "env:CONTROL_PLANE_ORGANIZATION_ID"\n' if has_org else ""
    yaml_body = (
        "config_version: 1\n"
        "control_plane:\n"
        '  base_url: "https://api.openai.com"\n'
        f'  tunnel_id: "{tid}"\n'
        f'  {cp_field}: "{cp_ref}"\n'
        f"{org_line}"
        "health:\n"
        '  listen_addr: "127.0.0.1:18766"\n'
        "admin_ui:\n"
        "  open_browser: false\n"
        "log:\n"
        "  level: info\n"
        "  format: json\n"
        "mcp:\n"
        "  max_concurrent_requests: 32\n"
        "  extra_headers:\n"
        '    Authorization: "env:DOTS_GW_AUTH_HDR"\n'
        "  discovery_extra_headers:\n"
        '    Authorization: "env:DOTS_GW_AUTH_HDR"\n'
        '    X-Dots-Disable-OAuth: "1"\n'
        "  server_urls:\n"
        "    - channel: main\n"
        f'      url: "http://127.0.0.1:{lb_port}/mcp"\n'
    )
    yaml_p.write_text(yaml_body, encoding="utf-8")
    os.chmod(yaml_p, 0o600)
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
    print(f"8765||{pathlib.Path.home() / 'workspaces'}||True|True|18765")
    raise SystemExit(0)
d = json.loads(p.read_text(encoding="utf-8"))
port = d.get("port", 8765)
pub = d.get("public_ip") or ""
wdir = d.get("default_workdir") or ""
cert = d.get("tls_certfile") or ""
mns = d.get("isolate_mount_namespace", True)
sbx = d.get("agy_default_sandbox", True)
lb_port = d.get("loopback_http_port") or ""
print(f"{port}|{pub}|{wdir}|{cert}|{mns}|{sbx}|{lb_port}")
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
  IFS='|' read -r port cfg_ip wdir cert mns sbx lb_port <<<"$(read_cfg_info)"
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
  local agy_net
  agy_net="$(python3 - "${CONFIG_FILE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
print(bool(d.get("agy_sandbox_network_access", True)))
PY
)"
  echo "  Workspace Jail   : ${wdir} (mount_ns=${mns}, agy_sandbox=${sbx}, agy_net=${agy_net})"
  local sb_info
  sb_info="$(python3 - "${CONFIG_FILE}" <<'PY'
import json, os, pathlib, sys
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
sb_dir = d.get("sandbox_state_dir") or ("/mnt/data/dots-sandbox" if pathlib.Path("/mnt/data/dots-sandbox").is_dir() else str(pathlib.Path.home() / ".cache" / "dots-sandbox"))
min_d = d.get("sandbox_min_retention_days", 7)
max_d = d.get("sandbox_max_retention_days", 30)
max_agy = d.get("max_concurrent_agy", 3)
max_cdx = d.get("max_concurrent_codex", 6)
agt_to_h = float(d.get("agent_default_timeout_seconds", 28800.0)) / 3600.0
max_to_h = float(d.get("max_timeout_seconds", 86400.0)) / 3600.0
try:
    st = os.statvfs(sb_dir if os.path.exists(sb_dir) else os.path.dirname(sb_dir))
    free_gb = (st.f_frsize * st.f_bavail) / (1024 ** 3)
    print(f"{sb_dir} (free={free_gb:.1f} GiB, retention={min_d:g}d..{max_d:g}d, agy={max_agy}, codex={max_cdx}, timeout={agt_to_h:g}h..{max_to_h:g}h)")
except OSError:
    print(f"{sb_dir} (retention={min_d:g}d..{max_d:g}d, agy={max_agy}, codex={max_cdx}, timeout={agt_to_h:g}h..{max_to_h:g}h)")
PY
)"
  echo "  Sandbox Store    : ${sb_info}"
  local agy_auth_summary codex_ver codex_auth_state
  agy_auth_summary="$(python3 - "${AGY_ENV_FILE}" <<'PY'
import pathlib, sys
env_p = pathlib.Path(sys.argv[1])
vals = {}
if env_p.is_file():
    for raw in env_p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("unset "):
            vals.pop(s[6:].strip(), None)
            continue
        if s.startswith("export "):
            s = s[7:].strip()
        if "=" in s:
            k, v = s.split("=", 1)
            vals[k.strip()] = v.strip().strip("'").strip('"')
adc_on = vals.get("AGY_ADC_AUTH", "").lower() in ("1", "true", "yes", "on")
proj = vals.get("GOOGLE_CLOUD_QUOTA_PROJECT", "")
if adc_on:
    print(f"auth=adc{f', project={proj}' if proj else ''}")
else:
    print("auth=oauth")
PY
)"
  codex_ver="$(command -v codex >/dev/null 2>&1 && codex --version 2>/dev/null || /usr/local/bin/codex --version 2>/dev/null || echo 'not installed')"
  if is_codex_auth_configured; then
    codex_auth_state="auth=configured"
  else
    codex_auth_state="auth=pending (run 'dots-gateway codex-setup')"
  fi
  echo "  Local Agents     : agy (${agy_auth_summary}, model=$(current_agy_model_label)) + ${codex_ver} (${codex_auth_state})"
  echo "  AGY Plugins      : $(agy_plugins_summary)"
  echo "  Codex Plugins    : $(codex_plugins_summary)"
  echo "  Docker Access    : $(docker_access_summary)"

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
    if [[ -n "${lb_port}" ]]; then
      echo "  Tunnel Transport : http-streamable -> http://127.0.0.1:${lb_port}/mcp (concurrent)"
    fi
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
  sync_tunnel_streamable_http
  IFS='|' read -r port _ _ cert _ _ _ <<<"$(read_cfg_info)"
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

drain_and_snapshot_before_restart() {
  local force_restart="$1"
  local wait_forever="$2"
  if ! systemctl --user is-active --quiet "${SERVICE_NAME}"; then
    return 0
  fi
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    return 0
  fi

  if [[ "${force_restart}" != "1" ]]; then
    local max_wait="${DOTS_RESTART_DRAIN_SECONDS:-120}"
    local elapsed=0
    while true; do
      local active_cnt
      active_cnt="$(python3 - "${CONFIG_FILE}" <<'PY'
import json, pathlib, ssl, sys, urllib.request
try:
    cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    toks = cfg.get("api_" + "tokens") or []
    if not toks:
        print("0")
        raise SystemExit(0)
    port = int(cfg.get("port") or 8765)
    scheme = "https" if (cfg.get("tls_certfile") and cfg.get("tls_keyfile")) else "http"
    req = urllib.request.Request(
        f"{scheme}://127.0.0.1:{port}/v1/health",
        headers={"Authorization": f"Bearer {toks[0]}"},
    )
    ctx = ssl._create_unverified_context() if scheme == "https" else None
    with urllib.request.urlopen(req, context=ctx, timeout=2.5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        print(int(data.get("active_sessions") or 0))
except Exception:
    print("0")
PY
)"
      if [[ ! "${active_cnt}" =~ ^[0-9]+$ ]] || (( active_cnt == 0 )); then
        break
      fi
      if [[ "${wait_forever}" != "1" ]] && (( elapsed >= max_wait )); then
        echo "❌ 检测到当前仍有 ${active_cnt} 个活跃会话正在运行 (已等待 ${elapsed}s)，为避免中断任务已取消重启。" >&2
        echo "   可使用 '${PROG_NAME} restart --wait' 等待全部任务自然结束后重启，或 '${PROG_NAME} restart --force' 强制立即重启。" >&2
        return 1
      fi
      if (( elapsed == 0 )); then
        echo "==> Draining ${active_cnt} active session(s) before restarting ${SERVICE_NAME} ..."
      fi
      sleep 2
      elapsed=$(( elapsed + 2 ))
    done
  fi

  # Snapshot in-memory sessions to disk ledger before stopping (seamless across upgrades)
  python3 - "${CONFIG_FILE}" <<'PY'
import json, os, pathlib, ssl, sys, urllib.request
try:
    cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    toks = cfg.get("api_" + "tokens") or []
    if not toks:
        raise SystemExit(0)
    port = int(cfg.get("port") or 8765)
    scheme = "https" if (cfg.get("tls_certfile") and cfg.get("tls_keyfile")) else "http"
    ctx = ssl._create_unverified_context() if scheme == "https" else None
    hdrs = {"Authorization": f"Bearer {toks[0]}"}
    sdir = pathlib.Path(cfg.get("session_state_dir") or (pathlib.Path.home() / ".config" / "dots-gateway" / "sessions")).expanduser()
    sdir.mkdir(parents=True, exist_ok=True)
    os.chmod(sdir, 0o700)
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{port}/v1/sessions", headers=hdrs)
    with urllib.request.urlopen(req, context=ctx, timeout=3.0) as resp:
        items = json.loads(resp.read().decode("utf-8")).get("sessions") or []
    for item in items[:200]:
        sid = str(item.get("session_id") or "")
        if not sid or (sdir / f"{sid}.json").exists():
            continue
        dreq = urllib.request.Request(f"{scheme}://127.0.0.1:{port}/v1/sessions/{sid}", headers=hdrs)
        with urllib.request.urlopen(dreq, context=ctx, timeout=3.0) as dresp:
            det = json.loads(dresp.read().decode("utf-8"))
        argv = det.get("argv") or []
        exe0 = os.path.basename(argv[0]) if argv else ""
        is_agy = bool(det.get("session_kind") == "agy" or exe0 == "agy")
        is_codex = bool(det.get("session_kind") == "codex" or exe0 == "codex")
        rec = {
            "schema_version": 1,
            "session_id": sid,
            "session_kind": "agy" if is_agy else ("codex" if is_codex else "exec"),
            "is_agy": is_agy,
            "is_codex": is_codex,
            "status": det.get("status") or "completed",
            "pid": det.get("pid"),
            "boot_id": boot_id,
            "proc_start_ticks": None,
            "agent_conversation_id": det.get("agent_conversation_id"),
            "argv": argv,
            "shell_cmd": det.get("shell_cmd"),
            "cwd": det.get("cwd") or "",
            "returncode": det.get("returncode"),
            "started_at": det.get("started_at"),
            "ended_at": det.get("ended_at"),
            "last_seq": det.get("last_seq") or 1,
            "stdout": str(det.get("stdout") or "")[-65536:],
            "stderr": str(det.get("stderr") or "")[-65536:],
            "stdout_truncated": bool(det.get("stdout_truncated", False)),
            "stderr_truncated": bool(det.get("stderr_truncated", False)),
            "reconciled_after_restart": False,
        }
        tmp_f = sdir / f"{sid}.snap.tmp"
        tmp_f.write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp_f, 0o600)
        os.replace(tmp_f, sdir / f"{sid}.json")
except Exception:
    pass
PY
}

cmd_restart() {
  local force_restart="0"
  local wait_forever="0"
  for arg in "$@"; do
    case "${arg}" in
      -f|--force) force_restart="1" ;;
      -w|--wait|--drain) wait_forever="1" ;;
    esac
  done
  ensure_unit_installed
  ensure_local_client_json
  sync_tunnel_streamable_http
  drain_and_snapshot_before_restart "${force_restart}" "${wait_forever}" || exit 1
  IFS='|' read -r port _ _ cert _ _ _ <<<"$(read_cfg_info)"
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

  echo "==> Generating concurrent Streamable HTTP tunnel-client profile (dots-gateway) ..."
  sync_tunnel_streamable_http "${tunnel_id}"

  IFS='|' read -r port _ _ cert _ _ _ <<<"$(read_cfg_info)"
  if ! systemctl --user is-active --quiet "${SERVICE_NAME}"; then
    echo "==> Starting ${SERVICE_NAME} so tunnel-client doctor can probe local MCP ..."
    systemctl --user start "${SERVICE_NAME}"
    wait_for_health "${port}" "${cert}" || true
  fi

  echo "==> Validating tunnel configuration with 'tunnel-client doctor' ..."
  systemctl --user stop "${TUNNEL_SERVICE_NAME}" 2>/dev/null || true
  set -a
  # shellcheck disable=SC1090
  source "${TUNNEL_ENV_FILE}"
  set +a
  local tunnel_bin
  tunnel_bin="$(command -v tunnel-client || echo /usr/local/bin/tunnel-client)"
  "${tunnel_bin}" doctor --profile dots-gateway --explain

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

cmd_codex_setup() {
  ensure_local_client_json
  local var_oai="OPENAI_API""_KEY"
  local var_base="OPENAI_BASE_URL"
  local oai_val="${!var_oai:-}"
  local base_val="${!var_base:-}"

  if [[ -z "${oai_val}" ]]; then
    read -rsp "请输入用于本机 Codex CLI 的 OpenAI API Key (输入不回显): " oai_val
    echo ""
  fi
  oai_val="$(printf "%s" "${oai_val}" | tr -d '[:space:]')"
  if [[ -z "${oai_val}" ]]; then
    echo "ERROR: API Key 不能为空。" >&2
    exit 1
  fi

  if [[ -z "${base_val}" && -t 0 ]]; then
    read -rp "可选自定义 Base URL (默认使用 OpenAI 官方接口，直接回车跳过): " base_val
    base_val="$(printf "%s" "${base_val}" | tr -d '[:space:]')"
  fi

  mkdir -p "${CLIENT_CONFIG_DIR}" "${HOME}/.codex"
  chmod 700 "${CLIENT_CONFIG_DIR}" "${HOME}/.codex"
  umask 077
  {
    printf "# Isolated OpenAI Codex CLI environment (0600, injected only into run_codex)\n"
    printf "%s=%s\n" "${var_oai}" "${oai_val}"
    if [[ -n "${base_val}" ]]; then
      printf "%s=%s\n" "${var_base}" "${base_val}"
    fi
  } > "${CODEX_ENV_FILE}"
  chmod 600 "${CODEX_ENV_FILE}"

  if command -v codex >/dev/null 2>&1; then
    printf "%s\n" "${oai_val}" | codex login --with-api-key >/dev/null
    chmod 600 "${HOME}/.codex/auth.json" 2>/dev/null || true
    echo "==> Verifying Codex login status ..."
    codex login status || true
  fi
  echo "✅ Codex CLI 凭证已安全保存至 ${CODEX_ENV_FILE} (0600) 及 ~/.codex/auth.json (即时生效，无需重启网关)。"
}

cmd_agy_auth() {
  ensure_local_client_json
  mkdir -p "${CLIENT_CONFIG_DIR}"
  chmod 700 "${CLIENT_CONFIG_DIR}"

  local subcmd="${1:-}"
  local arg_proj="${2:-}"

  # Read current state and auto-detect quota project
  local cur_mode cur_proj adc_file_status adc_json_proj
  IFS='|' read -r cur_mode cur_proj adc_file_status adc_json_proj <<<"$(python3 - "${AGY_ENV_FILE}" <<'PY'
import json, os, pathlib, sys
env_p = pathlib.Path(sys.argv[1])
vals = {}
last_proj = ""
if env_p.is_file():
    for raw in env_p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s.startswith("# LAST_QUOTA_PROJECT="):
            last_proj = s.split("=", 1)[1].strip()
            continue
        if not s or s.startswith("#"):
            continue
        if s.startswith("unset "):
            vals.pop(s[6:].strip(), None)
            continue
        if s.startswith("export "):
            s = s[7:].strip()
        if "=" in s:
            k, v = s.split("=", 1)
            vals[k.strip()] = v.strip().strip("'").strip('"')

adc_json = pathlib.Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
adc_ok = "missing"
json_proj = ""
if adc_json.is_file():
    try:
        d = json.loads(adc_json.read_text(encoding="utf-8"))
        adc_ok = f"present ({d.get('type', 'unknown')})"
        json_proj = str(d.get("quota_project_id") or "").strip()
    except Exception:
        adc_ok = "present"

adc_on = vals.get("AGY_ADC_AUTH", "").lower() in ("1", "true", "yes", "on")
mode = "adc" if adc_on else "oauth"
proj = vals.get("GOOGLE_CLOUD_QUOTA_PROJECT") or last_proj or json_proj or os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT", "")
print(f"{mode}|{proj}|{adc_ok}|{json_proj}")
PY
)"

  print_agy_auth_status() {
    echo "============================================================================"
    echo "  Antigravity CLI (agy) Authentication Profile (Hot-Reload / 免重启切换)"
    echo "============================================================================"
    if [[ "${cur_mode}" == "adc" ]]; then
      echo "  Current Mode     : ADC (Google Cloud Application Default Credentials)"
      echo "  AGY_ADC_AUTH     : true"
      echo "  Quota Project    : ${cur_proj:-<unset>}"
    else
      echo "  Current Mode     : OAuth (Default ~/.gemini OAuth login)"
      echo "  AGY_ADC_AUTH     : <unset>"
      echo "  Saved ADC Project: ${cur_proj:-<unset>}"
    fi
    echo "  ADC Credentials  : ~/.config/gcloud/application_default_credentials.json (${adc_file_status})"
    echo "  Hot-Reload File  : ${AGY_ENV_FILE}"
    echo "----------------------------------------------------------------------------"
    echo "  快速切换命令 (即时生效，无需重启网关):"
    echo "    ${PROG_NAME} agy-auth adc [PROJECT_ID]  # 切换为 Google Cloud ADC 认证"
    echo "    ${PROG_NAME} agy-auth oauth             # 切换回默认 OAuth 认证"
    echo "    ${PROG_NAME} agy-auth toggle            # 在 ADC 与 OAuth 之间一键切换"
    echo "    ${PROG_NAME} agy-auth status            # 查看当前认证状态"
    echo "============================================================================"
  }

  if [[ -z "${subcmd}" ]]; then
    print_agy_auth_status
    if [[ ! -t 0 ]]; then
      return 0
    fi
    local choice=""
    read -rp "请选择要切换的认证模式 [1=ADC, 2=OAuth, t=一键切换, 直接回车保持不变]: " choice
    choice="$(printf "%s" "${choice}" | tr -d '[:space:]')"
    case "${choice}" in
      1|adc|ADC) subcmd="adc" ;;
      2|oauth|OAUTH) subcmd="oauth" ;;
      t|T|toggle|switch) subcmd="toggle" ;;
      "") return 0 ;;
      *)
        echo "ERROR: 无效选项 '${choice}'" >&2
        exit 1
        ;;
    esac
  fi

  case "${subcmd}" in
    status|show|info)
      print_agy_auth_status
      return 0
      ;;
    toggle|switch)
      if [[ "${cur_mode}" == "adc" ]]; then
        subcmd="oauth"
      else
        subcmd="adc"
      fi
      ;;
  esac

  case "${subcmd}" in
    adc|gcloud|on|enable)
      local target_proj="${arg_proj:-${cur_proj:-${adc_json_proj:-}}}"
      if [[ -z "${target_proj}" ]] && command -v gcloud >/dev/null 2>&1; then
        target_proj="$(gcloud config get-value project 2>/dev/null | tr -d '[:space:]' || true)"
        [[ "${target_proj}" == "(unset)" ]] && target_proj=""
      fi
      if [[ -z "${target_proj}" && -t 0 ]]; then
        read -rp "请输入 GOOGLE_CLOUD_QUOTA_PROJECT (例如 my-gcp-project): " target_proj
        target_proj="$(printf "%s" "${target_proj}" | tr -d '[:space:]')"
      fi
      umask 077
      {
        printf "# Isolated Antigravity CLI (agy) auth profile (0600, hot-reloaded per run_agy session)\n"
        printf "# Mode: adc\n"
        if [[ -n "${target_proj}" ]]; then
          printf "# LAST_QUOTA_PROJECT=%s\n" "${target_proj}"
        fi
        printf "export AGY_ADC_AUTH=true\n"
        if [[ -n "${target_proj}" ]]; then
          printf "export GOOGLE_CLOUD_QUOTA_PROJECT=%s\n" "${target_proj}"
        fi
      } > "${AGY_ENV_FILE}"
      chmod 600 "${AGY_ENV_FILE}"
      cur_mode="adc"
      cur_proj="${target_proj}"
      ;;
    oauth|default|off|disable|reset)
      umask 077
      {
        printf "# Isolated Antigravity CLI (agy) auth profile (0600, hot-reloaded per run_agy session)\n"
        printf "# Mode: oauth\n"
        if [[ -n "${cur_proj}" ]]; then
          printf "# LAST_QUOTA_PROJECT=%s\n" "${cur_proj}"
        fi
        printf "unset AGY_ADC_AUTH\n"
        printf "unset GOOGLE_CLOUD_QUOTA_PROJECT\n"
      } > "${AGY_ENV_FILE}"
      chmod 600 "${AGY_ENV_FILE}"
      cur_mode="oauth"
      ;;
    *)
      echo "ERROR: 未知的 agy-auth 子命令 '${subcmd}' (可选: adc | oauth | toggle | status)" >&2
      exit 1
      ;;
  esac

  # Ensure ~/.bashrc dynamically sources ~/.config/dots-gateway/agy.env instead of hardcoding exports
  python3 - "${HOME}/.bashrc" "${AGY_ENV_FILE}" <<'PY'
import pathlib, re, sys
rc_p = pathlib.Path(sys.argv[1])
if not rc_p.is_file():
    raise SystemExit(0)
raw = rc_p.read_text(encoding="utf-8")
lines = []
for ln in raw.splitlines():
    s = ln.strip()
    if re.match(r"^(export\s+)?(AGY_ADC_AUTH|GOOGLE_CLOUD_QUOTA_PROJECT)=", s):
        continue
    if s == "# Antigravity CLI auth profile (managed by 'dots-gateway agy-auth')":
        continue
    if "dots-gateway/agy.env" in s:
        continue
    lines.append(ln)
while lines and not lines[-1].strip():
    lines.pop()
lines.append("")
lines.append("# Antigravity CLI auth profile (managed by 'dots-gateway agy-auth')")
lines.append('[ -f "$HOME/.config/dots-gateway/agy.env" ] && . "$HOME/.config/dots-gateway/agy.env"')
rc_p.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  if [[ "${cur_mode}" == "adc" ]]; then
    if [[ ! -f "${HOME}/.config/gcloud/application_default_credentials.json" ]]; then
      echo "⚠️  提示: 未检测到 ~/.config/gcloud/application_default_credentials.json，请先执行 'gcloud auth application-default login'。" >&2
    fi
    echo "✅ Antigravity (agy) 已切换为 [ADC 认证模式] (AGY_ADC_AUTH=true${cur_proj:+, GOOGLE_CLOUD_QUOTA_PROJECT=${cur_proj}}) — 网关侧即时生效，无需重启！"
  else
    echo "✅ Antigravity (agy) 已切换回 [默认 OAuth 认证模式] (已清除 AGY_ADC_AUTH) — 网关侧即时生效，无需重启！"
  fi
  echo "💡 当前交互终端如需同步更新环境变量，可执行: source ~/.bashrc"
}

# Print the effective gateway default agy model (agy.model > config.json agy_default_model > agy settings.json)
current_agy_model_label() {
  python3 - "${AGY_MODEL_FILE}" "${CONFIG_FILE}" <<'PY'
import json, pathlib, sys
mf = pathlib.Path(sys.argv[1])
if mf.is_file():
    for ln in mf.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            print(s)
            raise SystemExit(0)
try:
    d = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
    m = str(d.get("agy_default_model") or "").strip()
    if m:
        print(f"{m} (config.json)")
        raise SystemExit(0)
except (OSError, ValueError):
    pass
sp = pathlib.Path.home() / ".gemini" / "antigravity-cli" / "settings.json"
try:
    m = str(json.loads(sp.read_text(encoding="utf-8")).get("model") or "").strip()
except (OSError, ValueError):
    m = ""
print(f"follow-agy-settings{f': {m}' if m else ''}")
PY
}

# Run `agy models` with the gateway's agy auth profile; prints "id<TAB>name" lines
fetch_agy_models() {
  (
    set +u
    if [[ -f "${AGY_ENV_FILE}" ]]; then
      # shellcheck disable=SC1090
      . "${AGY_ENV_FILE}"
    fi
    local agy_bin
    agy_bin="$(command -v agy || echo "${HOME}/.local/bin/agy")"
    timeout 60 "${agy_bin}" models 2>/dev/null | grep $'\t' || true
  )
}

cmd_agy_model() {
  ensure_local_client_json
  mkdir -p "${CLIENT_CONFIG_DIR}"
  chmod 700 "${CLIENT_CONFIG_DIR}"

  local subcmd="${1:-}"
  local target="${2:-}"

  print_agy_model_status() {
    echo "============================================================================"
    echo "  Antigravity CLI (agy) Gateway Default Model (Hot-Reload / 免重启切换)"
    echo "============================================================================"
    echo "  Default Model    : $(current_agy_model_label)"
    echo "  Hot-Reload File  : ${AGY_MODEL_FILE}"
    echo "  优先级           : run_agy 的 model 参数 > agy.model > config.json agy_default_model > agy settings.json"
    echo "----------------------------------------------------------------------------"
    echo "  快速切换命令 (即时生效，无需重启网关):"
    echo "    ${PROG_NAME} agy-model list              # 列出当前认证下可用模型"
    echo "    ${PROG_NAME} agy-model set <MODEL_ID>    # 设置网关默认模型 (可简写为 agy-model <MODEL_ID>)"
    echo "    ${PROG_NAME} agy-model reset             # 清除网关默认值, 跟随本地 agy 的 /model 选择"
    echo "    ${PROG_NAME} agy-model status            # 查看当前默认模型"
    echo "============================================================================"
  }

  case "${subcmd}" in
    ""|status|show|info)
      print_agy_model_status
      if [[ -z "${subcmd}" && -t 0 ]]; then
        local models choice idx=0
        models="$(fetch_agy_models)"
        if [[ -z "${models}" ]]; then
          echo "⚠️  无法获取可用模型列表 (请检查 'dots-gateway agy-auth status')。" >&2
          return 0
        fi
        local -a ids=()
        while IFS=$'\t' read -r mid mname; do
          [[ -z "${mid}" ]] && continue
          idx=$((idx + 1))
          ids+=("${mid}")
          printf "  %2d) %-28s %s\n" "${idx}" "${mid}" "${mname}"
        done <<<"${models}"
        echo "   0) 跟随本地 agy settings.json (reset)"
        read -rp "请选择默认模型编号 (直接回车保持不变): " choice
        choice="$(printf "%s" "${choice}" | tr -d '[:space:]')"
        [[ -z "${choice}" ]] && return 0
        if [[ "${choice}" == "0" ]]; then
          subcmd="reset"
        elif [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#ids[@]} )); then
          subcmd="set"
          target="${ids[$((choice - 1))]}"
        else
          echo "ERROR: 无效选项 '${choice}'" >&2
          exit 1
        fi
      else
        return 0
      fi
      ;;
    list|ls|models)
      local models
      models="$(fetch_agy_models)"
      if [[ -z "${models}" ]]; then
        echo "ERROR: 无法获取可用模型列表 (请检查 'dots-gateway agy-auth status')。" >&2
        exit 1
      fi
      local cur
      cur="$(current_agy_model_label)"
      echo "可用模型 (当前网关默认: ${cur}):"
      while IFS=$'\t' read -r mid mname; do
        [[ -z "${mid}" ]] && continue
        local mark="  "
        [[ "${cur}" == "${mid}" ]] && mark="* "
        printf "  %s%-28s %s\n" "${mark}" "${mid}" "${mname}"
      done <<<"${models}"
      return 0
      ;;
  esac

  case "${subcmd}" in
    set|use)
      ;;
    reset|clear|default|unset)
      rm -f "${AGY_MODEL_FILE}"
      echo "✅ 已清除网关默认模型，run_agy 未指定 model 时将跟随本地 agy 选择 ($(current_agy_model_label)) — 即时生效，无需重启！"
      return 0
      ;;
    *)
      # Shorthand: `agy-model <MODEL_ID>`
      target="${subcmd}"
      ;;
  esac

  target="$(printf "%s" "${target}" | tr -d '[:space:]')"
  if [[ -z "${target}" ]]; then
    echo "ERROR: 请指定模型 ID，例如: ${PROG_NAME} agy-model set gemini-2.5-pro" >&2
    exit 1
  fi
  if [[ ! "${target}" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
    echo "ERROR: 模型 ID '${target}' 含非法字符 (仅允许字母、数字、. _ -)。" >&2
    exit 1
  fi

  local models
  models="$(fetch_agy_models)"
  if [[ -n "${models}" ]] && ! cut -f1 <<<"${models}" | grep -qxF "${target}"; then
    echo "ERROR: 模型 '${target}' 不在当前认证可用列表中。可用模型:" >&2
    cut -f1 <<<"${models}" | sed 's/^/    /' >&2
    exit 1
  elif [[ -z "${models}" ]]; then
    echo "⚠️  无法获取可用模型列表，跳过校验直接写入。" >&2
  fi

  umask 077
  local tmp_f="${AGY_MODEL_FILE}.tmp.$$"
  {
    printf "# Gateway default agy model (managed by 'dots-gateway agy-model', hot-reloaded per run_agy)\n"
    printf "%s\n" "${target}"
  } > "${tmp_f}"
  chmod 600 "${tmp_f}"
  mv -f "${tmp_f}" "${AGY_MODEL_FILE}"
  echo "✅ 网关默认 agy 模型已设置为 [${target}] — 即时生效，无需重启！(run_agy 显式传入 model 时仍以调用参数为准)"
}

resolve_docker_paths() {
  # Honour optional config.json overrides (docker_mode_file / docker_proxy_socket)
  local out
  out="$(python3 - "${CONFIG_FILE}" <<'PY' 2>/dev/null || true
import json, os, sys
try:
    c = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    c = {}
print(os.path.expanduser(c.get("docker_mode_file") or ""))
print(os.path.expanduser(c.get("docker_proxy_socket") or ""))
PY
)"
  local mf ps
  mf="$(sed -n 1p <<<"${out}")"
  ps="$(sed -n 2p <<<"${out}")"
  [[ -n "${mf}" ]] && DOCKER_MODE_FILE="${mf}"
  [[ -n "${ps}" ]] && DOCKER_PROXY_SOCKET="${ps}"
  return 0
}

current_docker_mode() {
  local v=""
  if [[ -f "${DOCKER_MODE_FILE}" ]]; then
    v="$(grep -v '^[[:space:]]*#' "${DOCKER_MODE_FILE}" | sed 's/#.*//' | tr -d '[:space:]' | head -n1 | tr '[:upper:]' '[:lower:]')"
  fi
  case "${v}" in
    1|true|yes|on|enable|enabled) echo "on" ;;
    0|false|no|off|disable|disabled) echo "off" ;;
    *)
      if python3 -c "import json,sys; sys.exit(0 if json.load(open('${CONFIG_FILE}')).get('docker_enabled') else 1)" 2>/dev/null; then
        echo "on"
      else
        echo "off"
      fi
      ;;
  esac
}

docker_proxy_listening() {
  [[ -S "${DOCKER_PROXY_SOCKET}" ]] || return 1
  curl -s -o /dev/null --max-time 3 --unix-socket "${DOCKER_PROXY_SOCKET}" http://docker/_ping
}

docker_access_summary() {
  resolve_docker_paths
  local mode proxy daemon
  mode="$(current_docker_mode)"
  if docker_proxy_listening; then proxy="proxy=listening"; else proxy="proxy=down"; fi
  if [[ -S /var/run/docker.sock ]]; then daemon="daemon=present"; else daemon="daemon=absent"; fi
  echo "${mode} (${proxy}, ${daemon}; host socket masked in sandbox)"
}

write_docker_mode() {
  local mode="$1"
  mkdir -p "$(dirname "${DOCKER_MODE_FILE}")"
  chmod 700 "$(dirname "${DOCKER_MODE_FILE}")" 2>/dev/null || true
  local tmp_f="${DOCKER_MODE_FILE}.tmp.$$"
  {
    printf "# Gateway sandbox Docker access (managed by 'dots-gateway docker', hot-reloaded per session)\n"
    printf "%s\n" "${mode}"
  } > "${tmp_f}"
  chmod 600 "${tmp_f}"
  mv -f "${tmp_f}" "${DOCKER_MODE_FILE}"
}

cmd_docker() {
  resolve_docker_paths
  local subcmd="${1:-status}"
  case "${subcmd}" in
    on|enable)
      write_docker_mode on
      echo "✅ 网关沙箱 Docker 访问已开启 — 新会话即时生效，无需重启。"
      echo "   exec_command / run_agy / run_codex 中的 docker / docker compose 将经由策略过滤代理访问 daemon"
      echo "   (仅允许挂载工作区目录；禁止 --privileged / --cap-add / --device / --pid=host 等；端口默认仅绑定 127.0.0.1)"
      docker_proxy_listening || echo "⚠️  代理 socket 未就绪 (${DOCKER_PROXY_SOCKET})：如为首次升级，请执行 '${PROG_NAME} restart'。"
      ;;
    off|disable)
      write_docker_mode off
      echo "✅ 网关沙箱 Docker 访问已关闭 — 新会话即时生效 (宿主 docker.sock 在沙箱中始终被屏蔽)。"
      ;;
    toggle)
      if [[ "$(current_docker_mode)" == "on" ]]; then cmd_docker off; else cmd_docker on; fi
      ;;
    status)
      echo "Docker Access : $(current_docker_mode)  (mode file: ${DOCKER_MODE_FILE})"
      if docker_proxy_listening; then
        echo "Proxy Socket  : ${DOCKER_PROXY_SOCKET} (listening)"
      else
        echo "Proxy Socket  : ${DOCKER_PROXY_SOCKET} (down — '${PROG_NAME} restart' 以加载代理)"
      fi
      if [[ -S /var/run/docker.sock ]]; then
        echo "Docker Daemon : $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'present (host user cannot query)')"
      else
        echo "Docker Daemon : not installed / socket absent"
      fi
      ;;
    test)
      if ! docker_proxy_listening; then
        echo "ERROR: 代理 socket 未就绪 (${DOCKER_PROXY_SOCKET})" >&2
        exit 1
      fi
      local v code
      v="$(curl -s --max-time 10 --unix-socket "${DOCKER_PROXY_SOCKET}" http://docker/version)"
      echo "GET /version           -> ${v:0:160}"
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --unix-socket "${DOCKER_PROXY_SOCKET}" \
        -H 'Content-Type: application/json' -d '{"Image":"alpine","HostConfig":{"Privileged":true}}' \
        http://docker/containers/create)"
      echo "privileged create      -> HTTP ${code} (期望 403)"
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --unix-socket "${DOCKER_PROXY_SOCKET}" \
        -H 'Content-Type: application/json' -d '{"Image":"alpine","HostConfig":{"Binds":["/:/host"]}}' \
        http://docker/containers/create)"
      echo "bind / create          -> HTTP ${code} (期望 403)"
      ;;
    *)
      echo "ERROR: 未知的 docker 子命令 '${subcmd}' (可选: on | off | toggle | status | test)" >&2
      exit 1
      ;;
  esac
}

agy_plugins_summary() {
  python3 - "${CONFIG_FILE}" "${GATEWAY_DIR}" "${AGY_PLUGINS_FILE}" <<'PY' 2>/dev/null || echo "off (default)"
import os, pathlib, sys
cfg_p = pathlib.Path(sys.argv[1])
gw_dir = sys.argv[2]
pf_override = sys.argv[3]
if gw_dir not in sys.path:
    sys.path.insert(0, gw_dir)
if pf_override:
    os.environ.setdefault("GATEWAY_AGY_PLUGINS_FILE", pf_override)
from gateway.config import GatewayConfig
from gateway.policy import CommandPolicy

cfg = GatewayConfig.load(cfg_p) if cfg_p.is_file() else GatewayConfig(agy_plugins_file=pf_override)
info = CommandPolicy(cfg).get_agy_plugins_info()
status = info.get("status")
plugins = info.get("plugins") or []
cfg_dirs = info.get("configured_dirs") or []
if status == "active":
    names = ", ".join(f"{p['name']}(ro)" for p in plugins)
    print(f"on [{names}] (source={info.get('source')})")
elif status == "error":
    print(f"ERROR ({info.get('error')})")
else:
    if cfg_dirs:
        print(f"off ({len(cfg_dirs)} registered dir(s) staged; run 'dots-gateway agy-plugins on')")
    else:
        print("off (default; isolated)")
PY
}

cmd_agy_plugins() {
  mkdir -p "${CLIENT_CONFIG_DIR}"
  chmod 700 "${CLIENT_CONFIG_DIR}" 2>/dev/null || true

  python3 - "${CONFIG_FILE}" "${GATEWAY_DIR}" "${AGY_PLUGINS_FILE}" "${PROG_NAME}" "$@" <<'PY'
import dataclasses
import errno
import fcntl
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

cfg_path = pathlib.Path(sys.argv[1])
gw_dir = sys.argv[2]
plugins_file_arg = sys.argv[3]
prog_name = sys.argv[4]
cli_args = sys.argv[5:]

if gw_dir not in sys.path:
    sys.path.insert(0, gw_dir)
if plugins_file_arg:
    os.environ["GATEWAY_AGY_PLUGINS_FILE"] = plugins_file_arg

from gateway.config import GatewayConfig, agy_plugins_config_state, redact_diagnostic_text
from gateway.policy import CommandPolicy
from gateway.sandbox import (
    SandboxStorageError,
    build_mount_ns_argv,
    can_use_mount_namespace,
    prepare_sandbox_runtime_state,
)

cfg = (
    GatewayConfig.load(cfg_path)
    if cfg_path.is_file()
    else GatewayConfig(agy_plugins_file=plugins_file_arg)
)
if plugins_file_arg:
    cfg.agy_plugins_file = plugins_file_arg

plugins_file = pathlib.Path(os.path.abspath(os.path.expanduser(cfg.agy_plugins_file)))
lock_timeout = max(0.05, float(cfg.sandbox_lock_timeout_seconds or 5.0))


def _err(msg: str, code: int = 1) -> "None":
    safe = redact_diagnostic_text(str(msg), cfg)
    print(f"ERROR: {safe}", file=sys.stderr)
    raise SystemExit(code)


def _acquire_file_lock(lock_path: pathlib.Path) -> int:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(lock_path.parent, 0o700)
    except OSError:
        pass
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(lock_path), flags, 0o600)
    except OSError as exc:
        _err(f"Cannot open plugin registry lock '{lock_path}': {exc}")
    deadline = time.monotonic() + lock_timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                os.close(fd)
                _err(f"flock failed on '{lock_path}': {exc}")
            if time.monotonic() >= deadline:
                os.close(fd)
                _err(
                    f"Timed out after {lock_timeout:.2f}s waiting for plugin registry lock '{lock_path}'"
                )
            time.sleep(0.05)


def _write_plugins_state_atomic(enabled: bool, dirs: list[str]) -> None:
    plugins_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(plugins_file.parent, 0o700)
    except OSError:
        pass
    if plugins_file.is_symlink():
        _err(f"Refusing to write symlinked agy_plugins_file '{plugins_file}'")
    payload = {
        "schema_version": 1,
        "enabled": bool(enabled),
        "plugin_dirs": list(dirs),
    }
    tmp_p = plugins_file.parent / f".{plugins_file.name}.tmp.{os.getpid()}"
    try:
        if tmp_p.exists() or tmp_p.is_symlink():
            tmp_p.unlink()
        tmp_p.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(tmp_p, 0o600)
        os.replace(tmp_p, plugins_file)
    except OSError as exc:
        try:
            tmp_p.unlink(missing_ok=True)
        except OSError:
            pass
        _err(f"Failed to write '{plugins_file}': {exc}")


def _validate_candidate_dirs(cand_dirs: list[str]) -> list:
    probe_cfg = dataclasses.replace(
        cfg,
        agy_plugins_enabled=True,
        agy_plugin_dirs=list(cand_dirs),
        agy_plugins_file=str(plugins_file.parent / f".nonexistent-probe-{os.getpid()}.json"),
    )
    pol = CommandPolicy(probe_cfg)
    return pol.validate_agy_plugins(require_mount_ns_check=False)


def _print_status() -> None:
    pol = CommandPolicy(cfg)
    info = pol.get_agy_plugins_info()
    print("============================================================================")
    print("  Antigravity CLI (agy) Trusted Read-Only Plugins (Hot-Reload / 免重启管理)")
    print("============================================================================")
    print(f"  Status           : {info.get('status')} (enabled={info.get('enabled')})")
    print(f"  Config Source    : {info.get('source')}")
    print(f"  Hot-Reload File  : {info.get('plugins_file')}")
    print(f"  Runtime Home     : {info.get('agent_runtime_home_root')} (隔离发现根，避免受保护 HOME deny 拦截)")
    print(f"  Plugin State Dir : {info.get('plugin_state_dir')} (Hook 临时队列与运行态专用)")
    cfg_dirs = info.get("configured_dirs") or []
    if cfg_dirs:
        print(f"  Registered Dirs  : {len(cfg_dirs)}")
        for idx, d in enumerate(cfg_dirs, 1):
            print(f"    {idx}) {d}")
    else:
        print("  Registered Dirs  : <none> (默认关闭，与原行为完全一致)")
    active_plgs = info.get("plugins") or []
    if active_plgs:
        print("  Active Mappings  :")
        for p in active_plgs:
            print(
                f"    - {p['name']} [{p['mode']}, {p['manifest']}, hook-jail=enforced]: "
                f"{p['source_dir']} -> {p['vfs_discovery_dir']}"
            )
    if info.get("error"):
        print(f"  Policy Error     : {info.get('error')}")
    print("----------------------------------------------------------------------------")
    print("  运维命令 (仅限宿主管理员操作，任务不可动态覆盖；即时生效，无需重启网关):")
    print(f"    {prog_name} agy-plugins add <PLUGIN_DIR> [--enable]  # 校验并登记可信插件目录")
    print(f"    {prog_name} agy-plugins on                           # 开启已登记插件只读挂载与读取授权")
    print(f"    {prog_name} agy-plugins off                          # 一键关闭插件能力并回滚至隔离态")
    print(f"    {prog_name} agy-plugins remove <PLUGIN_DIR>          # 移除单个插件目录")
    print(f"    {prog_name} agy-plugins clear                        # 清空登记并恢复默认关闭态")
    print(f"    {prog_name} agy-plugins doctor                       # 执行目录边界、Hook 沙箱与只读自检")
    print("============================================================================")


subcmd = cli_args[0].strip().lower() if cli_args else "status"
rest = cli_args[1:]

if subcmd in ("status", "show", "info", "list", "ls"):
    _print_status()
    raise SystemExit(0)

if subcmd in ("add", "register"):
    enable_now = False
    raw_targets: list[str] = []
    for tok in rest:
        if tok in ("--enable", "-e", "--on"):
            enable_now = True
        else:
            raw_targets.append(tok)
    if len(raw_targets) != 1 or not raw_targets[0].strip():
        _err(f"Usage: {prog_name} agy-plugins add <PLUGIN_DIR> [--enable]")
    cand = os.path.abspath(os.path.expanduser(raw_targets[0].strip()))

    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = agy_plugins_config_state(cfg)
        if state.get("config_error"):
            _err(f"Existing agy-plugins registry is corrupted: {state['config_error']}")
        cur_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
        new_dirs = list(cur_dirs)
        if cand not in new_dirs:
            new_dirs.append(cand)
        try:
            validated = _validate_candidate_dirs(new_dirs)
        except Exception as exc:
            _err(str(exc))
        new_enabled = True if enable_now else bool(state.get("enabled"))
        _write_plugins_state_atomic(new_enabled, new_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    names = ", ".join(p.name for p in validated)
    print(f"✅ 已通过安全边界与 Hook 清单校验并登记 AGY 插件目录: {cand} (plugins: {names})")
    if not new_enabled:
        print(f"💡 当前处于默认关闭态，确认无误后执行 '{prog_name} agy-plugins on' 即可免重启启用。")
    else:
        print("✅ 插件隔离发现、只读挂载与 Hook 沙箱已即时生效 (无需重启网关)。")
    raise SystemExit(0)

if subcmd in ("on", "enable"):
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = agy_plugins_config_state(cfg)
        if state.get("config_error"):
            _err(state["config_error"])
        cur_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
        if not cur_dirs:
            _err(
                f"尚未登记任何插件目录；请先执行 '{prog_name} agy-plugins add <PLUGIN_DIR>' 再启用。"
            )
        try:
            validated = _validate_candidate_dirs(cur_dirs)
        except Exception as exc:
            _err(str(exc))
        _write_plugins_state_atomic(True, cur_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    names = ", ".join(f"{p.name} -> {p.vfs_discovery_dir}" for p in validated)
    print(f"✅ AGY 已登记插件已启用 [{names}] — 新 run_agy 会话即时生效，无需重启！")
    raise SystemExit(0)

if subcmd in ("off", "disable"):
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = agy_plugins_config_state(cfg)
        cur_dirs = (
            [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
            if not state.get("config_error")
            else []
        )
        _write_plugins_state_atomic(False, cur_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
    print("✅ AGY 插件挂载已关闭并回滚至隔离状态 — 新会话即时生效，无需重启！")
    raise SystemExit(0)

if subcmd in ("remove", "rm", "del", "unregister"):
    if len(rest) != 1 or not rest[0].strip():
        _err(f"Usage: {prog_name} agy-plugins remove <PLUGIN_DIR>")
    target = os.path.abspath(os.path.expanduser(rest[0].strip()))
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = agy_plugins_config_state(cfg)
        if state.get("config_error"):
            _err(state["config_error"])
        cur_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
        new_dirs = [d for d in cur_dirs if d != target]
        if len(new_dirs) == len(cur_dirs):
            _err(f"Plugin directory '{target}' is not registered")
        new_enabled = bool(state.get("enabled")) and bool(new_dirs)
        if new_enabled:
            try:
                _validate_candidate_dirs(new_dirs)
            except Exception as exc:
                _err(str(exc))
        _write_plugins_state_atomic(new_enabled, new_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
    print(f"✅ 已移除插件目录: {target} (enabled={new_enabled})")
    raise SystemExit(0)

if subcmd in ("clear", "reset"):
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        if cfg.agy_plugins_enabled or cfg.agy_plugin_dirs:
            _write_plugins_state_atomic(False, [])
        else:
            try:
                if plugins_file.is_symlink() or plugins_file.exists():
                    plugins_file.unlink()
            except OSError as exc:
                _err(f"Failed to remove '{plugins_file}': {exc}")
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
    print("✅ 已清空已登记 AGY 插件并恢复默认关闭态 — 即时生效，无需重启！")
    raise SystemExit(0)

if subcmd in ("doctor", "check", "verify"):
    from gateway.config import effective_plugin_state_dir
    from gateway.hook_jail import cleanup_prepared_plugin_runtime, prepare_agy_plugin_runtime

    require_mns = "--require-mount-ns" in rest
    state = agy_plugins_config_state(cfg)
    if state.get("config_error"):
        _err(f"[1/4] 配置状态检查失败: {state['config_error']}")
    enabled = bool(state.get("enabled"))
    raw_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
    print(f"[1/4] 配置状态检查通过: enabled={enabled}, source={state.get('source')}, dirs={len(raw_dirs)}")

    try:
        sb_root = prepare_sandbox_runtime_state(
            cfg.sandbox_state_dir,
            lock_timeout_seconds=lock_timeout,
            forbidden_roots=raw_dirs,
        )
    except Exception as exc:
        _err(f"[2/4] 沙箱运行态与锁健康检查失败: {exc}")
    print(f"[2/4] 沙箱运行态与锁健康检查通过: {sb_root} (tmp 写入探针正常)")

    validated = []
    prepared_rt = None
    try:
        if raw_dirs:
            try:
                validated = _validate_candidate_dirs(raw_dirs)
            except Exception as exc:
                _err(f"[3/4] 插件三类目录隔离、符号链接与 Hook 清单检查失败: {exc}")
            probe_active_cfg = dataclasses.replace(
                cfg,
                agy_plugins_enabled=True,
                agy_plugin_dirs=list(raw_dirs),
                agy_plugins_file=str(plugins_file.parent / f".nonexistent-doc-{os.getpid()}.json"),
            )
            probe_pol = CommandPolicy(probe_active_cfg)
            try:
                settings_obj = probe_pol.build_agy_sandbox_settings()
                probe_cwd_abs = os.path.abspath(os.path.expanduser(cfg.default_workdir))
                prepared_rt = prepare_agy_plugin_runtime(
                    probe_active_cfg,
                    validated_plugins=validated,
                    sandbox_state_root=sb_root,
                    allowed_workspaces=[probe_cwd_abs, *probe_pol._allowed_roots],
                    masked_paths=[str(pathlib.Path(gw_dir).resolve()), *cfg.protected_paths],
                    readonly_subpaths=[],
                )
            except Exception as exc:
                _err(f"[3/4] AGY --settings 规则与 Hook 沙箱打包失败: {exc}")
            allow_rules = set((settings_obj.get("permissions") or {}).get("allow") or [])
            from gateway.policy import _paths_overlap_any_direction

            for plg in validated:
                for req_p in (plg.source_dir, plg.vfs_discovery_dir):
                    if f"read_file({req_p})" not in allow_rules:
                        _err(f"[3/4] 缺少只读授权规则 read_file({req_p})")
                for rule in allow_rules:
                    if rule.startswith("write_file(") and rule.endswith(")"):
                        wr_p = os.path.abspath(os.path.expanduser(rule[len("write_file(") : -1].strip()))
                        if _paths_overlap_any_direction(
                            wr_p, plg.source_dir
                        ) or _paths_overlap_any_direction(wr_p, plg.vfs_discovery_dir):
                            _err(f"[3/4] 检测到危险可写规则泄漏: {rule}")
            print(
                "[3/4] 三类目录边界、隔离发现路径、Hook 沙箱重写与 AGY --settings 只读规则检查通过: "
                + ", ".join(f"{p.name}({p.source_dir} -> {p.vfs_discovery_dir})" for p in validated)
            )
        else:
            if enabled:
                _err("[3/4] agy_plugins_enabled=true 但未配置任何插件目录")
            print("[3/4] 当前未登记插件目录 (默认关闭态兼容校验通过)")

        mns_ok = can_use_mount_namespace()
        if not mns_ok:
            if require_mns:
                _err("[4/4] 当前内核/容器环境不支持 unshare --user --mount")
            print("[4/4] 内核挂载命名空间探针跳过 (当前环境 unshare 受容器 seccomp 限制)")
            raise SystemExit(0)

        if validated and prepared_rt is not None:
            import shlex
            mount_pairs = [(p.name, p.source_dir) for p in validated]
            nested_hook_cfgs = []
            for b in prepared_rt.bundles:
                jdir = pathlib.Path(b.host_jail_config_dir)
                existing_cfgs = sorted(jdir.glob("*.json")) if jdir.is_dir() else []
                if existing_cfgs:
                    probe_payload = json.loads(existing_cfgs[0].read_text(encoding="utf-8"))
                    probe_payload["event_name"] = "SessionStart"
                    probe_payload["resolved_argv"] = ["/bin/true"]
                    pfile = jdir / "__doctor_probe.json"
                    pfile.write_text(json.dumps(probe_payload, indent=2) + "\n", encoding="utf-8")
                    os.chmod(pfile, 0o644)
                    nested_hook_cfgs.append(os.path.join(b.vfs_jail_config_dir, "__doctor_probe.json"))
            hook_probe_lines = "".join(
                f"python3 -I {shlex.quote(prepared_rt.vfs_runner_script)} --config {shlex.quote(hc)} < /dev/null\n"
                for hc in nested_hook_cfgs
            )
            iso_gh_dir = os.path.join(prepared_rt.isolated_home_dir, ".config", "gh")
            host_gh_protected = probe_pol.is_protected_path(
                str((pathlib.Path.home() / ".config" / "gh").resolve())
            ) and str((pathlib.Path.home() / ".config" / "gh").resolve()) in {
                str(pathlib.Path(x).expanduser().resolve())
                for x in (cfg.protected_paths or [])
                if str(x).strip()
            }
            gh_iso_line = (
                ""
                if host_gh_protected
                else f"[ -d {shlex.quote(iso_gh_dir)} ] && [ -w {shlex.quote(iso_gh_dir)} ] || {{ echo 'gh_ro_or_missing' >&2; exit 24; }}\n"
            )
            probe_script = (
                "set -eu\n"
                "for d in \"$@\"; do\n"
                "  [ -d \"$d\" ] || { echo \"missing:$d\" >&2; exit 21; }\n"
                "  if ( : > \"$d/.dots_ro_probe\" ) 2>/dev/null; then\n"
                "    rm -f \"$d/.dots_ro_probe\" 2>/dev/null || true\n"
                "    echo \"writable:$d\" >&2; exit 22;\n"
                "  fi\n"
                "done\n"
                "if [ -e \"$HOME/.config/dots-gateway/config.json\" ] || [ -e \"$HOME/.config/dots-gateway/tunnel.env\" ]; then\n"
                "  echo 'secret_exposed' >&2; exit 23;\n"
                "fi\n"
                + gh_iso_line
                + hook_probe_lines
            )
            check_targets = []
            for p in validated:
                check_targets.extend([p.source_dir, p.vfs_discovery_dir])
            probe_cwd = pathlib.Path(cfg.default_workdir).expanduser()
            probe_cwd.mkdir(parents=True, exist_ok=True)
            ns_argv = build_mount_ns_argv(
                ["/bin/sh", "-c", probe_script, "sh", *check_targets],
                cwd=str(probe_cwd),
                allowed_workdirs=cfg.allowed_workdirs,
                protected_paths=cfg.protected_paths,
                is_agy=True,
                sandbox_state_dir=cfg.sandbox_state_dir,
                agy_plugins_enabled=True,
                agy_plugin_mounts=mount_pairs,
                prepared_plugin_runtime=prepared_rt,
                agent_runtime_home_root=cfg.agent_runtime_home_root,
                masked_plugin_paths=probe_pol.get_configured_agy_plugin_paths(),
                sandbox_lock_timeout_seconds=lock_timeout,
                plugin_state_dir=effective_plugin_state_dir(cfg),
            )
            proc = subprocess.run(ns_argv, capture_output=True, text=True, timeout=15)
            if proc.returncode != 0:
                _err(
                    f"[4/4] 真实沙箱 VFS 只读挂载与嵌套 Hook 沙箱探针失败 (rc={proc.returncode}): "
                    f"{proc.stderr.strip() or proc.stdout.strip()}"
                )
            if not host_gh_protected:
                exec_probe = (
                    "set -eu\n"
                    "[ -d \"$HOME/.config/gh\" ] && [ -w \"$HOME/.config/gh\" ] || { echo 'exec_gh_ro_or_missing' >&2; exit 25; }\n"
                    "if [ -e \"$HOME/.config/dots-gateway/config.json\" ] || [ -e \"$HOME/.config/dots-gateway/tunnel.env\" ]; then\n"
                    "  echo 'exec_secret_exposed' >&2; exit 26;\n"
                    "fi\n"
                )
                exec_ns_argv = build_mount_ns_argv(
                    ["/bin/sh", "-c", exec_probe],
                    cwd=str(probe_cwd),
                    allowed_workdirs=cfg.allowed_workdirs,
                    protected_paths=cfg.protected_paths,
                    sandbox_state_dir=cfg.sandbox_state_dir,
                    masked_plugin_paths=probe_pol.get_configured_agy_plugin_paths(),
                    sandbox_lock_timeout_seconds=lock_timeout,
                    plugin_state_dir=effective_plugin_state_dir(cfg),
                )
                exec_proc = subprocess.run(exec_ns_argv, capture_output=True, text=True, timeout=15)
                if exec_proc.returncode != 0:
                    _err(
                        f"[4/4] exec_command 沙箱 ~/.config/gh 读写或凭据屏蔽探针失败 (rc={exec_proc.returncode}): "
                        f"{exec_proc.stderr.strip() or exec_proc.stdout.strip()}"
                    )
            print("[4/4] 真实沙箱 VFS 隔离发现、嵌套 Hook 沙箱、~/.config/gh 读写、只读挂载与凭据屏蔽探针通过")
        else:
            print("[4/4] 内核 unshare --user --mount 可用")
        raise SystemExit(0)
    finally:
        cleanup_prepared_plugin_runtime(prepared_rt)

_err(
    f"未知的 agy-plugins 子命令 '{subcmd}' (可选: status | add | on | off | remove | clear | doctor)"
)
PY
}

codex_plugins_summary() {
  python3 - "${CONFIG_FILE}" "${GATEWAY_DIR}" "${CODEX_PLUGINS_FILE}" <<'PY' 2>/dev/null || echo "off (default)"
import os, pathlib, sys
cfg_p = pathlib.Path(sys.argv[1])
gw_dir = sys.argv[2]
pf_override = sys.argv[3]
if gw_dir not in sys.path:
    sys.path.insert(0, gw_dir)
if pf_override:
    os.environ.setdefault("GATEWAY_CODEX_PLUGINS_FILE", pf_override)
from gateway.config import GatewayConfig
from gateway.policy import CommandPolicy

cfg = GatewayConfig.load(cfg_p) if cfg_p.is_file() else GatewayConfig(codex_plugins_file=pf_override)
info = CommandPolicy(cfg).get_codex_plugins_info()
status = info.get("status")
plugins = info.get("plugins") or []
cfg_dirs = info.get("configured_dirs") or []
if status == "active":
    names = ", ".join(f"{p['name']}@{p['marketplace']}(ro)" for p in plugins)
    print(f"on [{names}] (source={info.get('source')})")
elif status == "error":
    print(f"ERROR ({info.get('error')})")
else:
    if cfg_dirs:
        print(f"off ({len(cfg_dirs)} registered dir(s) staged; run 'dots-gateway codex-plugins on')")
    else:
        print("off (default; isolated)")
PY
}

cmd_codex_plugins() {
  mkdir -p "${CLIENT_CONFIG_DIR}"
  chmod 700 "${CLIENT_CONFIG_DIR}" 2>/dev/null || true

  python3 - "${CONFIG_FILE}" "${GATEWAY_DIR}" "${CODEX_PLUGINS_FILE}" "${PROG_NAME}" "$@" <<'PY'
import dataclasses
import errno
import fcntl
import json
import os
import pathlib
import subprocess
import sys
import time

cfg_path = pathlib.Path(sys.argv[1])
gw_dir = sys.argv[2]
plugins_file_arg = sys.argv[3]
prog_name = sys.argv[4]
cli_args = sys.argv[5:]

if gw_dir not in sys.path:
    sys.path.insert(0, gw_dir)
if plugins_file_arg:
    os.environ["GATEWAY_CODEX_PLUGINS_FILE"] = plugins_file_arg

from gateway.config import GatewayConfig, codex_plugins_config_state, redact_diagnostic_text
from gateway.hook_jail import prepare_codex_plugin_runtime
from gateway.policy import CommandPolicy
from gateway.sandbox import (
    build_mount_ns_argv,
    can_use_mount_namespace,
    prepare_sandbox_runtime_state,
)

cfg = (
    GatewayConfig.load(cfg_path)
    if cfg_path.is_file()
    else GatewayConfig(codex_plugins_file=plugins_file_arg)
)
if plugins_file_arg:
    cfg.codex_plugins_file = plugins_file_arg

plugins_file = pathlib.Path(os.path.abspath(os.path.expanduser(cfg.codex_plugins_file)))
lock_timeout = max(0.05, float(cfg.sandbox_lock_timeout_seconds or 5.0))


def _err(msg: str, code: int = 1) -> "None":
    safe = redact_diagnostic_text(str(msg), cfg)
    print(f"ERROR: {safe}", file=sys.stderr)
    raise SystemExit(code)


def _acquire_file_lock(lock_path: pathlib.Path) -> int:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(lock_path.parent, 0o700)
    except OSError:
        pass
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(lock_path), flags, 0o600)
    except OSError as exc:
        _err(f"Cannot open Codex plugin registry lock '{lock_path}': {exc}")
    deadline = time.monotonic() + lock_timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                os.close(fd)
                _err(f"flock failed on '{lock_path}': {exc}")
            if time.monotonic() >= deadline:
                os.close(fd)
                _err(
                    f"Timed out after {lock_timeout:.2f}s waiting for Codex plugin registry lock '{lock_path}'"
                )
            time.sleep(0.05)


def _write_plugins_state_atomic(enabled: bool, dirs: list[str]) -> None:
    plugins_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(plugins_file.parent, 0o700)
    except OSError:
        pass
    if plugins_file.is_symlink():
        _err(f"Refusing to write symlinked codex_plugins_file '{plugins_file}'")
    payload = {
        "schema_version": 1,
        "enabled": bool(enabled),
        "plugin_dirs": list(dirs),
    }
    tmp_p = plugins_file.parent / f".{plugins_file.name}.tmp.{os.getpid()}"
    try:
        if tmp_p.exists() or tmp_p.is_symlink():
            tmp_p.unlink()
        tmp_p.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(tmp_p, 0o600)
        os.replace(tmp_p, plugins_file)
    except OSError as exc:
        try:
            tmp_p.unlink(missing_ok=True)
        except OSError:
            pass
        _err(f"Failed to write '{plugins_file}': {exc}")


def _validate_candidate_dirs(cand_dirs: list[str]) -> list:
    probe_cfg = dataclasses.replace(
        cfg,
        codex_plugins_enabled=True,
        codex_plugin_dirs=list(cand_dirs),
        codex_plugins_file=str(plugins_file.parent / f".nonexistent-codex-probe-{os.getpid()}.json"),
    )
    pol = CommandPolicy(probe_cfg)
    return pol.validate_codex_plugins(require_mount_ns_check=False)


def _print_status() -> None:
    pol = CommandPolicy(cfg)
    info = pol.get_codex_plugins_info()
    print("============================================================================")
    print("  OpenAI Codex CLI Trusted Read-Only Plugins (Hot-Reload / 免重启管理)")
    print("============================================================================")
    print(f"  Status           : {info.get('status')} (enabled={info.get('enabled')})")
    print(f"  Config Source    : {info.get('source')}")
    print(f"  Hot-Reload File  : {info.get('plugins_file')}")
    print(f"  Runtime Home     : {info.get('agent_runtime_home_root')} (隔离 CODEX_HOME 发现根)")
    print(f"  Plugin State Dir : {info.get('plugin_state_dir')} (PLUGIN_DATA 与 Hook 临时态专用)")
    cfg_dirs = info.get("configured_dirs") or []
    if cfg_dirs:
        print(f"  Registered Dirs  : {len(cfg_dirs)}")
        for idx, d in enumerate(cfg_dirs, 1):
            print(f"    {idx}) {d}")
    else:
        print("  Registered Dirs  : <none> (默认关闭，与原行为完全一致)")
    active_plgs = info.get("plugins") or []
    if active_plgs:
        print("  Active Mappings  :")
        for p in active_plgs:
            print(
                f"    - {p['name']}@{p['marketplace']} v{p['version']} [{p['mode']}, {p['manifest']}, hook-jail=enforced]: "
                f"{p['source_dir']} -> {p['vfs_discovery_dir']}"
            )
    if info.get("error"):
        print(f"  Policy Error     : {info.get('error')}")
    print("----------------------------------------------------------------------------")
    print("  运维命令 (仅限宿主管理员操作，任务不可动态覆盖；即时生效，无需重启网关):")
    print(f"    {prog_name} codex-plugins add <PLUGIN_DIR> [--enable]  # 校验并登记可信 Codex 插件目录")
    print(f"    {prog_name} codex-plugins on                           # 开启已登记插件只读挂载与 Hook 沙箱")
    print(f"    {prog_name} codex-plugins off                          # 一键关闭插件能力并回滚至原行为")
    print(f"    {prog_name} codex-plugins remove <PLUGIN_DIR>          # 移除单个插件目录")
    print(f"    {prog_name} codex-plugins clear                        # 清空登记并恢复默认关闭态")
    print(f"    {prog_name} codex-plugins doctor                       # 执行目录边界、信任哈希与只读自检")
    print("============================================================================")


subcmd = cli_args[0].strip().lower() if cli_args else "status"
rest = cli_args[1:]

if subcmd in ("status", "show", "info", "list", "ls"):
    _print_status()
    raise SystemExit(0)

if subcmd in ("add", "register"):
    enable_now = False
    raw_targets: list[str] = []
    for tok in rest:
        if tok in ("--enable", "-e", "--on"):
            enable_now = True
        else:
            raw_targets.append(tok)
    if len(raw_targets) != 1 or not raw_targets[0].strip():
        _err(f"Usage: {prog_name} codex-plugins add <PLUGIN_DIR> [--enable]")
    cand = os.path.abspath(os.path.expanduser(raw_targets[0].strip()))

    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = codex_plugins_config_state(cfg)
        if state.get("config_error"):
            _err(f"Existing codex-plugins registry is corrupted: {state['config_error']}")
        cur_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
        new_dirs = list(cur_dirs)
        if cand not in new_dirs:
            new_dirs.append(cand)
        try:
            validated = _validate_candidate_dirs(new_dirs)
        except Exception as exc:
            _err(str(exc))
        new_enabled = True if enable_now else bool(state.get("enabled"))
        _write_plugins_state_atomic(new_enabled, new_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    names = ", ".join(f"{p.name}@{p.marketplace_name}" for p in validated)
    print(f"✅ 已通过安全边界与 Hook 清单校验并登记 Codex 插件目录: {cand} (plugins: {names})")
    if not new_enabled:
        print(f"💡 当前处于默认关闭态，确认无误后执行 '{prog_name} codex-plugins on' 即可免重启启用。")
    else:
        print("✅ Codex 隔离发现、信任哈希合成与 Hook 沙箱已即时生效 (无需重启网关)。")
    raise SystemExit(0)

if subcmd in ("on", "enable"):
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = codex_plugins_config_state(cfg)
        if state.get("config_error"):
            _err(state["config_error"])
        cur_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
        if not cur_dirs:
            _err(
                f"尚未登记任何插件目录；请先执行 '{prog_name} codex-plugins add <PLUGIN_DIR>' 再启用。"
            )
        try:
            validated = _validate_candidate_dirs(cur_dirs)
        except Exception as exc:
            _err(str(exc))
        _write_plugins_state_atomic(True, cur_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    names = ", ".join(f"{p.name}@{p.marketplace_name} -> {p.vfs_discovery_dir}" for p in validated)
    print(f"✅ Codex 已登记插件已启用 [{names}] — 新 run_codex 会话即时生效，无需重启！")
    raise SystemExit(0)

if subcmd in ("off", "disable"):
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = codex_plugins_config_state(cfg)
        cur_dirs = (
            [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
            if not state.get("config_error")
            else []
        )
        _write_plugins_state_atomic(False, cur_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
    print("✅ Codex 插件挂载已关闭并回滚至隔离状态 — 新会话即时生效，无需重启！")
    raise SystemExit(0)

if subcmd in ("remove", "rm", "del", "unregister"):
    if len(rest) != 1 or not rest[0].strip():
        _err(f"Usage: {prog_name} codex-plugins remove <PLUGIN_DIR>")
    target = os.path.abspath(os.path.expanduser(rest[0].strip()))
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        state = codex_plugins_config_state(cfg)
        if state.get("config_error"):
            _err(state["config_error"])
        cur_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
        new_dirs = [d for d in cur_dirs if d != target]
        if len(new_dirs) == len(cur_dirs):
            _err(f"Codex plugin directory '{target}' is not registered")
        new_enabled = bool(state.get("enabled")) and bool(new_dirs)
        if new_enabled:
            try:
                _validate_candidate_dirs(new_dirs)
            except Exception as exc:
                _err(str(exc))
        _write_plugins_state_atomic(new_enabled, new_dirs)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
    print(f"✅ 已移除 Codex 插件目录: {target} (enabled={new_enabled})")
    raise SystemExit(0)

if subcmd in ("clear", "reset"):
    lock_fd = _acquire_file_lock(plugins_file.parent / f".{plugins_file.name}.lock")
    try:
        if cfg.codex_plugins_enabled or cfg.codex_plugin_dirs:
            _write_plugins_state_atomic(False, [])
        else:
            try:
                if plugins_file.is_symlink() or plugins_file.exists():
                    plugins_file.unlink()
            except OSError as exc:
                _err(f"Failed to remove '{plugins_file}': {exc}")
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
    print("✅ 已清空已登记 Codex 插件并恢复默认关闭态 — 即时生效，无需重启！")
    raise SystemExit(0)

if subcmd in ("doctor", "check", "verify"):
    from gateway.config import effective_plugin_state_dir
    from gateway.hook_jail import cleanup_prepared_plugin_runtime

    require_mns = "--require-mount-ns" in rest
    state = codex_plugins_config_state(cfg)
    if state.get("config_error"):
        _err(f"[1/4] 配置状态检查失败: {state['config_error']}")
    enabled = bool(state.get("enabled"))
    raw_dirs = [os.path.abspath(os.path.expanduser(x)) for x in (state.get("raw_dirs") or [])]
    print(f"[1/4] 配置状态检查通过: enabled={enabled}, source={state.get('source')}, dirs={len(raw_dirs)}")

    try:
        sb_root = prepare_sandbox_runtime_state(
            cfg.sandbox_state_dir,
            lock_timeout_seconds=lock_timeout,
            forbidden_roots=raw_dirs,
        )
    except Exception as exc:
        _err(f"[2/4] 沙箱运行态与锁健康检查失败: {exc}")
    print(f"[2/4] 沙箱运行态与锁健康检查通过: {sb_root} (tmp 写入探针正常)")

    validated = []
    prepared_rt = None
    probe_pol = CommandPolicy(cfg)
    try:
        if raw_dirs:
            try:
                validated = _validate_candidate_dirs(raw_dirs)
            except Exception as exc:
                _err(f"[3/4] 插件三类目录隔离、符号链接与 Hook 清单检查失败: {exc}")
            probe_active_cfg = dataclasses.replace(
                cfg,
                codex_plugins_enabled=True,
                codex_plugin_dirs=list(raw_dirs),
                codex_plugins_file=str(plugins_file.parent / f".nonexistent-codex-doc-{os.getpid()}.json"),
            )
            probe_pol = CommandPolicy(probe_active_cfg)
            try:
                probe_cwd_abs = os.path.abspath(os.path.expanduser(cfg.default_workdir))
                prepared_rt = prepare_codex_plugin_runtime(
                    probe_active_cfg,
                    validated_plugins=validated,
                    sandbox_state_root=sb_root,
                    allowed_workspaces=[probe_cwd_abs, *probe_pol._allowed_roots],
                    masked_paths=[str(pathlib.Path(gw_dir).resolve()), *cfg.protected_paths],
                    readonly_subpaths=[],
                )
            except Exception as exc:
                _err(f"[3/4] Codex 隔离 config.toml、信任哈希与 Hook 沙箱打包失败: {exc}")
            print(
                "[3/4] 三类目录边界、隔离 CODEX_HOME、Hook 信任哈希与沙箱重写检查通过: "
                + ", ".join(f"{p.name}@{p.marketplace_name}({p.source_dir} -> {p.vfs_discovery_dir})" for p in validated)
            )
        else:
            if enabled:
                _err("[3/4] codex_plugins_enabled=true 但未配置任何插件目录")
            print("[3/4] 当前未登记 Codex 插件目录 (默认关闭态兼容校验通过)")

        mns_ok = can_use_mount_namespace()
        if not mns_ok:
            if require_mns:
                _err("[4/4] 当前内核/容器环境不支持 unshare --user --mount")
            print("[4/4] 内核挂载命名空间探针跳过 (当前环境 unshare 受容器 seccomp 限制)")
            raise SystemExit(0)

        if validated and prepared_rt is not None:
            import shlex
            mount_pairs = [(p.name, p.source_dir) for p in validated]
            nested_hook_cfgs = []
            for b in prepared_rt.bundles:
                jdir = pathlib.Path(b.host_jail_config_dir)
                existing_cfgs = sorted(jdir.glob("*.json")) if jdir.is_dir() else []
                if existing_cfgs:
                    probe_payload = json.loads(existing_cfgs[0].read_text(encoding="utf-8"))
                    probe_payload["event_name"] = "SessionStart"
                    probe_payload["resolved_argv"] = ["/bin/true"]
                    pfile = jdir / "__doctor_probe.json"
                    pfile.write_text(json.dumps(probe_payload, indent=2) + "\n", encoding="utf-8")
                    os.chmod(pfile, 0o644)
                    nested_hook_cfgs.append(os.path.join(b.vfs_jail_config_dir, "__doctor_probe.json"))
            hook_probe_lines = "".join(
                f"python3 -I {shlex.quote(prepared_rt.vfs_runner_script)} --config {shlex.quote(hc)} < /dev/null\n"
                for hc in nested_hook_cfgs
            )
            iso_gh_dir = os.path.join(prepared_rt.isolated_home_dir, ".config", "gh")
            host_gh_protected = probe_pol.is_protected_path(
                str((pathlib.Path.home() / ".config" / "gh").resolve())
            ) and str((pathlib.Path.home() / ".config" / "gh").resolve()) in {
                str(pathlib.Path(x).expanduser().resolve())
                for x in (cfg.protected_paths or [])
                if str(x).strip()
            }
            gh_iso_line = (
                ""
                if host_gh_protected
                else f"[ -d {shlex.quote(iso_gh_dir)} ] && [ -w {shlex.quote(iso_gh_dir)} ] || {{ echo 'gh_ro_or_missing' >&2; exit 24; }}\n"
            )
            probe_script = (
                "set -eu\n"
                "for d in \"$@\"; do\n"
                "  [ -d \"$d\" ] || { echo \"missing:$d\" >&2; exit 21; }\n"
                "  if ( : > \"$d/.dots_ro_probe\" ) 2>/dev/null; then\n"
                "    rm -f \"$d/.dots_ro_probe\" 2>/dev/null || true\n"
                "    echo \"writable:$d\" >&2; exit 22;\n"
                "  fi\n"
                "done\n"
                "if [ -e \"$HOME/.config/dots-gateway/config.json\" ] || [ -e \"$HOME/.config/dots-gateway/tunnel.env\" ]; then\n"
                "  echo 'secret_exposed' >&2; exit 23;\n"
                "fi\n"
                + gh_iso_line
                + hook_probe_lines
            )
            check_targets = []
            for p in validated:
                check_targets.extend([p.source_dir, p.vfs_discovery_dir])
            probe_cwd = pathlib.Path(cfg.default_workdir).expanduser()
            probe_cwd.mkdir(parents=True, exist_ok=True)
            ns_argv = build_mount_ns_argv(
                ["/bin/sh", "-c", probe_script, "sh", *check_targets],
                cwd=str(probe_cwd),
                allowed_workdirs=cfg.allowed_workdirs,
                protected_paths=cfg.protected_paths,
                is_codex=True,
                sandbox_state_dir=cfg.sandbox_state_dir,
                codex_plugins_enabled=True,
                codex_plugin_mounts=mount_pairs,
                prepared_plugin_runtime=prepared_rt,
                agent_runtime_home_root=cfg.agent_runtime_home_root,
                masked_plugin_paths=probe_pol.get_configured_codex_plugin_paths(),
                sandbox_lock_timeout_seconds=lock_timeout,
                plugin_state_dir=effective_plugin_state_dir(cfg),
            )
            proc = subprocess.run(ns_argv, capture_output=True, text=True, timeout=15)
            if proc.returncode != 0:
                _err(
                    f"[4/4] 真实沙箱 VFS 只读挂载与嵌套 Hook 沙箱探针失败 (rc={proc.returncode}): "
                    f"{proc.stderr.strip() or proc.stdout.strip()}"
                )
            print("[4/4] 真实沙箱 VFS 隔离 CODEX_HOME、嵌套 Hook 沙箱、只读挂载与凭据屏蔽探针通过")
        else:
            print("[4/4] 内核 unshare --user --mount 可用")
        raise SystemExit(0)
    finally:
        cleanup_prepared_plugin_runtime(prepared_rt)

_err(
    f"未知的 codex-plugins 子命令 '{subcmd}' (可选: status | add | on | off | remove | clear | doctor)"
)
PY
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
  tunnel-setup [ID]    交互式配置并启动 OpenAI 官方 Secure MCP Tunnel (tunnel-client 后台常驻)
  agy-auth [mode]      免重启切换 Antigravity CLI 认证方式: adc [PROJECT_ID] | oauth | toggle | status
  agy-model [cmd]      免重启切换网关 agy 默认模型: list | set <MODEL_ID> | reset | status
  agy-plugins [cmd]    免重启管理隔离只读 AGY 插件与 Hook 沙箱: status | add <DIR> | on | off | remove | clear | doctor
  codex-plugins [cmd]  免重启管理隔离只读 Codex 插件与 Hook 沙箱: status | add <DIR> | on | off | remove | clear | doctor
  docker [cmd]         免重启开关沙箱 Docker 访问 (策略过滤代理): on | off | toggle | status | test
  codex-setup          交互式配置本机 OpenAI Codex CLI 的 API Key (0600 隔离存储，即时生效)
  start                启动网关服务 (及已配置的 Tunnel 服务) 并执行健康检查
  stop                 停止网关与 Tunnel 后台服务
  restart              平滑排空活跃会话后重启网关与 Tunnel 服务 (支持 --wait / --force，别名: reload)
  status               查看网关、OpenAI Tunnel (/readyz)、证书及工作区隔离状态 (默认命令)
  logs [tunnel] [-f]   查看服务日志 (默认同时显示网关与 Tunnel；加 tunnel 仅看隧道；加 -f 实时追踪)
  config               打印直连远程 MCP URL 与密钥配置 (别名: mcp-config)
  sync-ip [IP]         自动探测当前公网 IP，签发/续期 Let's Encrypt 证书并重启 (别名: renew-cert)
  help                 显示本帮助信息 (同 -h / --help)

常用示例:
  ${PROG_NAME} tunnel-setup           # 绑定 OpenAI tunnel_... 与 Runtime Key 并启动官方隧道
  ${PROG_NAME} agy-plugins status     # 查看 AGY 只读插件隔离发现、Hook 沙箱与挂载状态
  ${PROG_NAME} codex-plugins status   # 查看 Codex 只读插件隔离发现、信任哈希与 Hook 沙箱状态
  ${PROG_NAME} status                 # 查看网关与 OpenAI 隧道实时连接状态
  ${PROG_NAME} restart                # 一键重启网关与隧道服务
  ${PROG_NAME} logs -f                # 实时滚动查看网关与隧道日志
  ${PROG_NAME} logs tunnel -f         # 仅查看 tunnel-client 实时日志
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
  codex-setup|setup-codex)
    cmd_codex_setup "$@"
    ;;
  agy-auth|auth-agy|agy-setup|setup-agy)
    cmd_agy_auth "$@"
    ;;
  agy-model|agy-models|model)
    cmd_agy_model "$@"
    ;;
  agy-plugins|agy-plugin|plugins)
    cmd_agy_plugins "$@"
    ;;
  codex-plugins|codex-plugin)
    cmd_codex_plugins "$@"
    ;;
  docker|docker-access)
    cmd_docker "$@"
    ;;
  start)
    cmd_start
    ;;
  stop)
    cmd_stop
    ;;
  restart|reload)
    cmd_restart "$@"
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
