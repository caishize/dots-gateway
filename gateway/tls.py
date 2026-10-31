"""Automatic TLS / mTLS certificate generation and SHA-256 fingerprint utilities."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import ssl
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


def discover_local_ips() -> List[str]:
    """Discover local IPv4/IPv6 addresses using `ip -o addr` (fallback to loopback)."""
    ips: List[str] = ["127.0.0.1", "::1"]
    try:
        proc = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            for idx, tok in enumerate(parts):
                if tok in ("inet", "inet6") and idx + 1 < len(parts):
                    addr = parts[idx + 1].split("/")[0].split("%")[0]
                    try:
                        ip_obj = ipaddress.ip_address(addr)
                        if not ip_obj.is_link_local and str(ip_obj) not in ips:
                            ips.append(str(ip_obj))
                    except ValueError:
                        pass
    except Exception:
        pass
    return ips


def _extract_leaf_pem(pem_text: str) -> str:
    """Extract the first X.509 certificate PEM block (supports multi-cert fullchain.pem)."""
    begin_marker = "-----BEGIN CERTIFICATE-----"
    end_marker = "-----END CERTIFICATE-----"
    start = pem_text.find(begin_marker)
    if start == -1:
        return pem_text
    end = pem_text.find(end_marker, start)
    if end == -1:
        return pem_text
    return pem_text[start : end + len(end_marker)] + "\n"


def compute_cert_sha256(cert_pem_path: str | Path) -> str:
    """Return lowercase hex SHA-256 fingerprint of the leaf DER-encoded X.509 certificate."""
    pem_text = _extract_leaf_pem(Path(cert_pem_path).read_text(encoding="utf-8"))
    der_bytes = ssl.PEM_cert_to_DER_cert(pem_text)
    return hashlib.sha256(der_bytes).hexdigest()


def _cert_contains_all_targets(cert_path: Path, targets: Sequence[str]) -> bool:
    """Check whether an existing certificate's X.509 SAN already includes all DNS/IP targets."""
    if not cert_path.exists():
        return False
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=True,
        )
        present_dns: set[str] = set()
        present_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for line in proc.stdout.splitlines():
            for entry in line.split(","):
                item = entry.strip()
                if item.startswith("DNS:"):
                    present_dns.add(item[4:].strip().lower())
                elif item.startswith("IP Address:"):
                    raw_ip = item[11:].strip()
                    try:
                        present_ips.add(ipaddress.ip_address(raw_ip))
                    except ValueError:
                        pass

        for t in targets:
            try:
                if ipaddress.ip_address(t) not in present_ips:
                    return False
            except ValueError:
                if t.strip().lower() not in present_dns:
                    return False
        return True
    except Exception:
        return False


def _run_openssl(args: List[str]) -> None:
    proc = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args[:3])} failed: {proc.stderr.strip()}")


def ensure_tls_pki(
    certs_dir: str | Path,
    extra_hosts: Optional[Sequence[str]] = None,
) -> Dict[str, str]:
    """Ensure Root CA, Server TLS cert/key, and Client mTLS cert/key exist in `certs_dir`.

    Returns paths and the server certificate's SHA-256 fingerprint for pinning.
    """
    cdir = Path(certs_dir)
    cdir.mkdir(parents=True, exist_ok=True)
    os.chmod(cdir, 0o700)

    ca_key = cdir / "ca.key"
    ca_crt = cdir / "ca.crt"
    server_key = cdir / "server.key"
    server_crt = cdir / "server.crt"
    client_key = cdir / "client.key"
    client_crt = cdir / "client.crt"

    # 1. Root CA (valid 10 years)
    if not ca_key.exists() or not ca_crt.exists():
        _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)])
        os.chmod(ca_key, 0o600)
        ca_ext = cdir / "ca_ext.cnf"
        ca_ext.write_text(
            "[req]\n"
            "distinguished_name = dn\n"
            "x509_extensions = v3_ca\n"
            "prompt = no\n"
            "[dn]\n"
            "CN = Dots Gateway Private Root CA\n"
            "O = Dots Gateway\n"
            "[v3_ca]\n"
            "basicConstraints = critical, CA:TRUE, pathlen:0\n"
            "keyUsage = critical, keyCertSign, cRLSign\n"
            "subjectKeyIdentifier = hash\n",
            encoding="utf-8",
        )
        try:
            _run_openssl(
                [
                    "req",
                    "-new",
                    "-x509",
                    "-sha256",
                    "-days",
                    "3650",
                    "-key",
                    str(ca_key),
                    "-out",
                    str(ca_crt),
                    "-config",
                    str(ca_ext),
                ]
            )
            os.chmod(ca_crt, 0o644)
        finally:
            ca_ext.unlink(missing_ok=True)

    # 2. Build SAN list (DNS + discovered local IPs + configured public IP/domain)
    dns_names: List[str] = ["localhost", "dots-gateway"]
    ip_addrs: List[str] = discover_local_ips()
    for item in extra_hosts or []:
        val = item.strip()
        if not val or val == "0.0.0.0" or val == "::":
            continue
        try:
            ip_str = str(ipaddress.ip_address(val))
            if ip_str not in ip_addrs:
                ip_addrs.append(ip_str)
        except ValueError:
            if val not in dns_names:
                dns_names.append(val)

    all_targets = dns_names + ip_addrs
    if not server_key.exists() or not _cert_contains_all_targets(server_crt, all_targets):
        if not server_key.exists():
            _run_openssl(
                ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(server_key)]
            )
            os.chmod(server_key, 0o600)

        san_entries = [f"DNS:{d}" for d in dns_names] + [f"IP:{i}" for i in ip_addrs]
        san_line = ",".join(san_entries)
        pid_tag = f"{os.getpid()}"
        csr_path = cdir / f"server.{pid_tag}.csr"
        ext_path = cdir / f"server_ext.{pid_tag}.cnf"
        tmp_crt = cdir / f"server.{pid_tag}.crt"
        ext_path.write_text(
            f"basicConstraints = critical, CA:FALSE\n"
            f"keyUsage = critical, digitalSignature, keyEncipherment\n"
            f"extendedKeyUsage = serverAuth\n"
            f"subjectAltName = {san_line}\n",
            encoding="utf-8",
        )
        try:
            _run_openssl(
                [
                    "req",
                    "-new",
                    "-key",
                    str(server_key),
                    "-subj",
                    "/CN=dots-gateway/O=Dots Gateway",
                    "-out",
                    str(csr_path),
                ]
            )
            _run_openssl(
                [
                    "x509",
                    "-req",
                    "-sha256",
                    "-days",
                    "825",
                    "-in",
                    str(csr_path),
                    "-CA",
                    str(ca_crt),
                    "-CAkey",
                    str(ca_key),
                    "-CAcreateserial",
                    "-out",
                    str(tmp_crt),
                    "-extfile",
                    str(ext_path),
                ]
            )
            os.chmod(tmp_crt, 0o644)
            os.replace(tmp_crt, server_crt)
        finally:
            csr_path.unlink(missing_ok=True)
            ext_path.unlink(missing_ok=True)
            tmp_crt.unlink(missing_ok=True)

    # 3. Client mTLS certificate (ready for `tls_require_client_cert: true`)
    if not client_key.exists() or not client_crt.exists():
        _run_openssl(
            ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(client_key)]
        )
        os.chmod(client_key, 0o600)
        csr_path = cdir / "client.csr"
        ext_path = cdir / "client_ext.cnf"
        ext_path.write_text(
            "basicConstraints = critical, CA:FALSE\n"
            "keyUsage = critical, digitalSignature\n"
            "extendedKeyUsage = clientAuth\n",
            encoding="utf-8",
        )
        try:
            _run_openssl(
                [
                    "req",
                    "-new",
                    "-key",
                    str(client_key),
                    "-subj",
                    "/CN=dots-openai-client/O=Dots Client",
                    "-out",
                    str(csr_path),
                ]
            )
            _run_openssl(
                [
                    "x509",
                    "-req",
                    "-sha256",
                    "-days",
                    "825",
                    "-in",
                    str(csr_path),
                    "-CA",
                    str(ca_crt),
                    "-CAkey",
                    str(ca_key),
                    "-CAcreateserial",
                    "-out",
                    str(client_crt),
                    "-extfile",
                    str(ext_path),
                ]
            )
            os.chmod(client_crt, 0o644)
        finally:
            csr_path.unlink(missing_ok=True)
            ext_path.unlink(missing_ok=True)

    fingerprint = compute_cert_sha256(server_crt)
    return {
        "ca_cert": str(ca_crt),
        "ca_key": str(ca_key),
        "server_cert": str(server_crt),
        "server_key": str(server_key),
        "client_cert": str(client_crt),
        "client_key": str(client_key),
        "server_fingerprint_sha256": fingerprint,
    }


def _create_single_server_ssl_context(
    certfile: str,
    keyfile: str,
    cafile: Optional[str] = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if require_client_cert:
        if not cafile:
            raise ValueError("tls_ca_file is required when tls_require_client_cert is enabled")
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=cafile)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def build_server_ssl_context(
    certfile: str,
    keyfile: str,
    cafile: Optional[str] = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """Create a hardened TLS 1.2+/1.3 server SSLContext with automatic cert hot-reload on renewal."""
    primary_ctx = _create_single_server_ssl_context(
        certfile=certfile,
        keyfile=keyfile,
        cafile=cafile,
        require_client_cert=require_client_cert,
    )

    def _stat_pair() -> Tuple[int, int]:
        return (os.stat(certfile).st_mtime_ns, os.stat(keyfile).st_mtime_ns)

    state: Dict[str, object] = {
        "mtimes": _stat_pair(),
        "active_ctx": primary_ctx,
    }

    def _sni_hot_reload(
        ssl_sock: ssl.SSLSocket, _server_name: Optional[str], _initial_ctx: ssl.SSLContext
    ) -> None:
        try:
            cur_mtimes = _stat_pair()
            if cur_mtimes != state["mtimes"]:
                fresh_ctx = _create_single_server_ssl_context(
                    certfile=certfile,
                    keyfile=keyfile,
                    cafile=cafile,
                    require_client_cert=require_client_cert,
                )
                state["active_ctx"] = fresh_ctx
                state["mtimes"] = cur_mtimes
            active = state["active_ctx"]
            if active is not primary_ctx and isinstance(active, ssl.SSLContext):
                ssl_sock.context = active
        except Exception:
            # Keep serving with last known-good SSLContext if renewal write is mid-flight
            active = state["active_ctx"]
            if active is not primary_ctx and isinstance(active, ssl.SSLContext):
                try:
                    ssl_sock.context = active
                except Exception:
                    pass

    primary_ctx.sni_callback = _sni_hot_reload
    return primary_ctx
