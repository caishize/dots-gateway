#!/usr/bin/env bash
# Issue & configure auto-renewing Let's Encrypt official IP certificate (`shortlived` profile)
# for Dots Gateway Remote MCP (`https://<PUBLIC_IP>:8765/mcp`).
# Requires inbound TCP port 80 open in cloud firewall for ACME HTTP-01 validation & renewal.

set -euo pipefail

GATEWAY_DIR="${GATEWAY_DIR:-$HOME/gateway}"
GATEWAY_USER="${GATEWAY_USER:-${SUDO_USER:-$(id -un)}}"
CERT_OUT_DIR="${GATEWAY_DIR}/certs_letsencrypt"
ACME_HOME="/root/.acme.sh"

TARGET_IP="${1:-}"
if [[ -z "${TARGET_IP}" ]]; then
  TARGET_IP="$(python3 -c 'import json, pathlib, sys; p = pathlib.Path(sys.argv[1]) / "config.json"; print((json.loads(p.read_text()).get("public_ip") or "").strip())' "${GATEWAY_DIR}")"
fi

if [[ -z "${TARGET_IP}" ]]; then
  echo "ERROR: Usage: $0 <PUBLIC_IP> (or set public_ip in ${GATEWAY_DIR}/config.json)" >&2
  exit 1
fi

SSLIP_DOMAIN="${TARGET_IP//./-}.sslip.io"

echo "==> [1/5] Preparing acme.sh for ${SSLIP_DOMAIN} & ${TARGET_IP} ..."
sudo env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND bash -c '
  set -euo pipefail
  if [[ ! -x "'"${ACME_HOME}"'/acme.sh" ]]; then
    curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o /tmp/acme_install.sh
    sh /tmp/acme_install.sh --install-online --home "'"${ACME_HOME}"'" --no-cron
    rm -f /tmp/acme_install.sh
  fi
  sed -i "/ACCOUNT_EMAIL/d" "'"${ACME_HOME}"'/account.conf" 2>/dev/null || true
'

echo "==> [2/5] Running Let'\''s Encrypt Staging preflight check on TCP port 80 ..."
sudo env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND \
  "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" \
  --issue --server letsencrypt_test \
  -d "${SSLIP_DOMAIN}" -d "${TARGET_IP}" \
  --standalone \
  --cert-profile shortlived \
  --keylength ec-256 \
  --days 3 \
  --force

echo "==> [3/5] Staging check succeeded! Issuing Production Let'\''s Encrypt certificate (${SSLIP_DOMAIN} + ${TARGET_IP}) ..."
sudo env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND \
  "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" \
  --issue --server letsencrypt \
  -d "${SSLIP_DOMAIN}" -d "${TARGET_IP}" \
  --standalone \
  --cert-profile shortlived \
  --keylength ec-256 \
  --days 3 \
  --force

echo "==> [4/5] Installing certificate into ${CERT_OUT_DIR} and configuring 12h systemd renewal timer ..."
mkdir -p "${CERT_OUT_DIR}"
chmod 700 "${CERT_OUT_DIR}"

RELOAD_SCRIPT="${CERT_OUT_DIR}/post_renew.sh"
cat > "${RELOAD_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
chown ${GATEWAY_USER}:${GATEWAY_USER} "${CERT_OUT_DIR}/fullchain.pem" "${CERT_OUT_DIR}/privkey.pem"
chmod 644 "${CERT_OUT_DIR}/fullchain.pem"
chmod 600 "${CERT_OUT_DIR}/privkey.pem"
EOF
chmod 755 "${RELOAD_SCRIPT}"

sudo env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND \
  "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" \
  --install-cert -d "${SSLIP_DOMAIN}" --ecc \
  --fullchain-file "${CERT_OUT_DIR}/fullchain.pem" \
  --key-file "${CERT_OUT_DIR}/privkey.pem" \
  --reloadcmd "${RELOAD_SCRIPT}"

sudo tee /etc/systemd/system/dots-gateway-acme-renew.service >/dev/null <<EOF
[Unit]
Description=Renew Let's Encrypt short-lived IP certificate for Dots Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${ACME_HOME}/acme.sh --cron --home ${ACME_HOME}
EOF

sudo tee /etc/systemd/system/dots-gateway-acme-renew.timer >/dev/null <<EOF
[Unit]
Description=Twice-daily renewal check for Dots Gateway Let's Encrypt IP certificate

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now dots-gateway-acme-renew.timer

echo "==> [5/5] Updating ${GATEWAY_DIR}/config.json and restarting dots-gateway.service ..."
(
  cd "${GATEWAY_DIR}"
  python3 -c '
import sys
from pathlib import Path
from gateway.config import GatewayConfig

cfg_path = Path("config.json")
cfg = GatewayConfig.load(cfg_path)
cfg.public_ip = sys.argv[1]
cfg.tls_certfile = str(Path("certs_letsencrypt/fullchain.pem").resolve())
cfg.tls_keyfile = str(Path("certs_letsencrypt/privkey.pem").resolve())
cfg.tls_ca_file = None
cfg.tls_require_client_cert = False
cfg.save(cfg_path)
' "${TARGET_IP}"
)
systemctl --user restart dots-gateway.service
sleep 1
systemctl --user is-active dots-gateway.service
echo "==> SUCCESS: Publicly trusted Let's Encrypt IP certificate active on https://${TARGET_IP}:8765/mcp"
