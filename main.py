#!/usr/bin/env python3
"""Entrypoint CLI for starting and configuring the Hardened Dots <-> Local Dev Gateway."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from gateway.config import GatewayConfig, hash_password_pbkdf2
from gateway.server import GatewayServer
from gateway.tls import compute_cert_sha256, ensure_tls_pki


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hardened Dots Bidirectional Remote Development Gateway (HTTPS/SSE + WSS)"
    )
    default_cfg = str(Path(__file__).resolve().parent / "config.json")
    parser.add_argument(
        "-c",
        "--config",
        default=default_cfg,
        help=f"Path to JSON configuration file (default: {default_cfg})",
    )
    parser.add_argument("--host", default=None, help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: 8765)")
    parser.add_argument(
        "--public-ip",
        default=None,
        help="Public IP or domain name to include in the TLS certificate SAN",
    )
    parser.add_argument(
        "--allow-ip",
        action="append",
        default=None,
        help="Allowed client IP or CIDR (repeatable, e.g. --allow-ip 203.0.113.0/24)",
    )
    parser.add_argument("--token", default=None, help="Add/override Bearer API token")
    parser.add_argument("--user", default=None, help="Basic auth username")
    parser.add_argument("--password", default=None, help="Basic auth plaintext password")
    parser.add_argument("--hmac-secret", default=None, help="HMAC-SHA256 shared secret")
    parser.add_argument("--workdir", default=None, help="Default working directory")
    parser.add_argument("--tls-cert", default=None, help="TLS certificate PEM file path")
    parser.add_argument("--tls-key", default=None, help="TLS private key PEM file path")
    parser.add_argument("--tls-ca", default=None, help="TLS Root CA PEM file path (for mTLS)")
    parser.add_argument(
        "--mtls",
        action="store_true",
        help="Require client certificate authentication (mutual TLS)",
    )
    parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Disable TLS (ONLY safe on 127.0.0.1 or encrypted private tunnels)",
    )
    parser.add_argument(
        "--init-only",
        action="store_true",
        help="Generate config.json & TLS certificates and exit without starting server",
    )
    return parser.parse_args()


async def async_main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args()
    cfg_path = Path(args.config)
    cfg = GatewayConfig.load(cfg_path)
    dirty = not cfg_path.exists()

    if args.host:
        cfg.host = args.host
        dirty = True
    if args.port is not None:
        cfg.port = args.port
        dirty = True
    if args.public_ip:
        cfg.public_ip = args.public_ip.strip()
        dirty = True
    if args.allow_ip:
        for ip_entry in args.allow_ip:
            if ip_entry not in cfg.allowed_client_ips:
                cfg.allowed_client_ips.append(ip_entry)
                dirty = True
    if args.token:
        if args.token not in cfg.api_tokens:
            cfg.api_tokens.insert(0, args.token)
            dirty = True
    if args.user and args.password:
        cfg.users[args.user] = hash_password_pbkdf2(args.password)
        dirty = True
    if args.hmac_secret:
        cfg.hmac_secret = args.hmac_secret
        dirty = True
    if args.workdir:
        cfg.default_workdir = args.workdir
        dirty = True
    if args.tls_cert:
        cfg.tls_certfile = args.tls_cert
        dirty = True
    if args.tls_key:
        cfg.tls_keyfile = args.tls_key
        dirty = True
    if args.tls_ca:
        cfg.tls_ca_file = args.tls_ca
        dirty = True
    if args.mtls:
        cfg.tls_require_client_cert = True
        dirty = True

    generated = cfg.ensure_credentials(save_path=None)
    if generated:
        dirty = True

    cert_fp = ""
    certs_dir = cfg_path.parent / "certs"
    if args.no_tls:
        cfg.tls_certfile = None
        cfg.tls_keyfile = None
    else:
        if not cfg.tls_certfile or not cfg.tls_keyfile or not Path(cfg.tls_certfile).exists():
            extra = [cfg.public_ip] if cfg.public_ip else []
            pki = ensure_tls_pki(certs_dir, extra_hosts=extra)
            cfg.tls_certfile = pki["server_cert"]
            cfg.tls_keyfile = pki["server_key"]
            cfg.tls_ca_file = pki["ca_cert"]
            cert_fp = pki["server_fingerprint_sha256"]
            dirty = True
        else:
            if cfg.public_ip and str(certs_dir) in str(cfg.tls_certfile):
                pki = ensure_tls_pki(certs_dir, extra_hosts=[cfg.public_ip])
                cert_fp = pki["server_fingerprint_sha256"]
            else:
                cert_fp = compute_cert_sha256(cfg.tls_certfile)

    if dirty:
        cfg.save(cfg_path)

    use_tls = bool(cfg.tls_certfile and cfg.tls_keyfile)
    scheme = "https" if use_tls else "http"
    ws_scheme = "wss" if use_tls else "ws"
    display_host = cfg.public_ip or cfg.host

    print("=" * 76)
    print("  Dots <-> Local Dev & Antigravity (agy) Hardened Gateway")
    print("=" * 76)
    print(f"  Config File         : {cfg_path}")
    print(f"  HTTPS/SSE Endpoint  : {scheme}://{display_host}:{cfg.port}")
    print(f"  WebSocket (Duplex)  : {ws_scheme}://{display_host}:{cfg.port}/v1/ws")
    print(f"  TLS Encryption      : {'ENABLED (TLS 1.2/1.3)' if use_tls else 'DISABLED (Plaintext)'}")
    if use_tls:
        print(f"  mTLS Client Cert    : {'REQUIRED' if cfg.tls_require_client_cert else f'OPTIONAL (certs in {certs_dir})'}")
        print(f"  TLS SHA256 Pin      : {cert_fp}")
    print(f"  Client IP Allowlist : {cfg.allowed_client_ips or 'ALL (authenticated)'}")
    print(f"  Default Workdir     : {cfg.default_workdir}")
    print(f"  Agy Binary          : {cfg.agy_binary} (skip_permissions={cfg.agy_default_skip_permissions})")
    print("-" * 76)
    print(f"  Bearer API Token    : {cfg.api_tokens[0]}")
    print(f"  HMAC-SHA256 Secret  : {cfg.hmac_secret}")
    if generated.get("password"):
        print(f"  Basic Auth User     : {generated['username']}")
        print(f"  Basic Auth Password : {generated['password']}  (PBKDF2 hash stored)")
    else:
        print(f"  Basic Auth Users    : {', '.join(cfg.users.keys())}")
    print("=" * 76)

    if args.init_only:
        return 0

    server = GatewayServer(cfg)
    host, port = await server.start()
    logging.getLogger("dots_gateway").info(
        "Gateway listening on %s://%s:%d (mTLS=%s)",
        scheme,
        host,
        port,
        cfg.tls_require_client_cert,
    )
    try:
        await server.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logging.getLogger("dots_gateway").info("Shutting down gateway...")
    finally:
        await server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
