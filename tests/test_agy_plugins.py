"""Dedicated security, isolation, fault-injection, and end-to-end tests for AGY plugins."""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import conftest  # noqa: F401
from dots_client import DotsGatewayClient, DotsWebSocketSession
from gateway.config import (
    GATEWAY_ROOT,
    GatewayConfig,
    hash_password_pbkdf2,
    redact_diagnostic_text,
)
from gateway.docker_proxy import DockerPolicyError, DockerRequestPolicy
from gateway.policy import CommandPolicy
from gateway.sandbox import (
    SandboxLockTimeoutError,
    SandboxStorageError,
    build_mount_ns_argv,
    can_use_mount_namespace,
    prepare_sandbox_runtime_state,
)
from gateway.server import GatewayServer


def _snapshot_tree(root: Path) -> dict[str, tuple[int, str]]:
    """Return relative-path -> (mode, sha256) snapshot of a directory tree."""
    snap: dict[str, tuple[int, str]] = {}
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        rel_dir = os.path.relpath(base, root)
        st_d = os.lstat(base)
        snap[f"dir:{rel_dir}"] = (stat.S_IMODE(st_d.st_mode), "")
        for fn in files:
            fp = Path(base) / fn
            rel_f = os.path.relpath(fp, root)
            st_f = os.lstat(fp)
            if stat.S_ISLNK(st_f.st_mode):
                snap[f"lnk:{rel_f}"] = (stat.S_IMODE(st_f.st_mode), os.readlink(fp))
            elif stat.S_ISREG(st_f.st_mode):
                digest = hashlib.sha256(fp.read_bytes()).hexdigest()
                snap[f"reg:{rel_f}"] = (stat.S_IMODE(st_f.st_mode), digest)
            else:
                snap[f"spc:{rel_f}"] = (st_f.st_mode, "")
    return snap


def _create_oh_my_agents_fixture(plugin_dir: Path, plugin_name: str = "oh-my-agents") -> Path:
    """Create a realistic oh-my-agents (gemini branch) plugin directory structure."""
    plugin_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(plugin_dir, 0o755)

    (plugin_dir / "plugin.json").write_text(
        json.dumps(
            {
                "name": plugin_name,
                "version": "0.9.0-gemini",
                "description": "Autonomous Harness guardrails & verification workflow for AGY",
                "skills": "./skills/",
                "hooks": "./hooks.json",
                "rules": "./rules/",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(plugin_dir / "plugin.json", 0o644)
    (plugin_dir / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python3 ./hooks/antigravity-adapter.py SessionStart",
                                }
                            ],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(plugin_dir / "hooks.json", 0o644)

    hooks_dir = plugin_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    os.chmod(hooks_dir, 0o755)
    adapter = hooks_dir / "antigravity-adapter.py"
    adapter.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys, tempfile\n"
        "event = sys.argv[1] if len(sys.argv) > 1 else 'unknown'\n"
        "# Ensure tempfile writes go to isolated TMPDIR, never plugin CWD\n"
        "with tempfile.NamedTemporaryFile(mode='w', delete=True) as tf:\n"
        "    tf.write('hook-ok')\n"
        "    tmp_path = tf.name\n"
        "print(json.dumps({\n"
        "    'hook_event': event,\n"
        "    'cwd': os.getcwd(),\n"
        "    'dont_write_bytecode': os.environ.get('PYTHONDONTWRITEBYTECODE'),\n"
        "    'tmp_used': tmp_path,\n"
        "}))\n",
        encoding="utf-8",
    )
    os.chmod(adapter, 0o755)

    skills_root = plugin_dir / "skills"
    skills_root.mkdir(parents=True, exist_ok=True)
    os.chmod(skills_root, 0o755)
    spec_skill = skills_root / "spec-to-task"
    spec_skill.mkdir(parents=True, exist_ok=True)
    os.chmod(spec_skill, 0o755)
    (spec_skill / "SKILL.md").write_text(
        "---\n"
        "name: spec-to-task\n"
        "description: Convert product specification into executable tasks.\n"
        "---\n"
        "# Spec-To-Task Workflow\n"
        "SPEC_TO_TASK_SENTINEL_OK\n",
        encoding="utf-8",
    )
    os.chmod(spec_skill / "SKILL.md", 0o644)

    verify_skill = skills_root / "verify"
    verify_skill.mkdir(parents=True, exist_ok=True)
    os.chmod(verify_skill, 0o755)
    (verify_skill / "SKILL.md").write_text(
        "---\n"
        "name: verify\n"
        "description: Write verification signals and metrics into the project workspace.\n"
        "---\n"
        "# Verify Write Contract\n"
        "- `.claude/signals/verify-latest.json`\n"
        "- `.claude/metrics/verify.jsonl`\n"
        "- `docs/exec-plans/active/*.json`\n",
        encoding="utf-8",
    )
    os.chmod(verify_skill / "SKILL.md", 0o644)

    rules_dir = plugin_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(rules_dir, 0o755)
    (rules_dir / "AGENTS.md").write_text("# Plugin Rules\n", encoding="utf-8")
    os.chmod(rules_dir / "AGENTS.md", 0o644)

    return plugin_dir


def _create_mock_agy_binary(bin_path: Path) -> Path:
    """Create a mock `agy` executable that enforces `--settings` deny > allow rules."""
    bin_path.parent.mkdir(parents=True, exist_ok=True)
    bin_path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, re, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "\n"
        "sleep_ms = int(os.environ.get('MOCK_SLEEP_MS', '0') or '0')\n"
        "if sleep_ms > 0:\n"
        "    time.sleep(sleep_ms / 1000.0)\n"
        "\n"
        "argv = sys.argv[1:]\n"
        "settings = {}\n"
        "add_dirs = []\n"
        "positional_args = []\n"
        "sandbox_flag = False\n"
        "i = 0\n"
        "while i < len(argv):\n"
        "    a = argv[i]\n"
        "    if a == '--':\n"
        "        positional_args.extend(argv[i + 1:])\n"
        "        break\n"
        "    elif a == '--sandbox':\n"
        "        sandbox_flag = True\n"
        "    elif a == '--settings' and i + 1 < len(argv):\n"
        "        settings = json.loads(argv[i + 1])\n"
        "        i += 1\n"
        "    elif a.startswith('--settings='):\n"
        "        settings = json.loads(a.split('=', 1)[1])\n"
        "    elif a == '--add-dir' and i + 1 < len(argv):\n"
        "        add_dirs.append(argv[i + 1])\n"
        "        i += 1\n"
        "    i += 1\n"
        "\n"
        "perms = settings.get('permissions') or {}\n"
        "allow_rules = perms.get('allow') or []\n"
        "deny_rules = perms.get('deny') or []\n"
        "\n"
        "def _extract(rules, prefix):\n"
        "    out = []\n"
        "    pat = re.compile(r'^' + re.escape(prefix) + r'\\((.*)\\)$')\n"
        "    for r in rules:\n"
        "        m = pat.match(str(r).strip())\n"
        "        if m:\n"
        "            out.append(os.path.abspath(os.path.expanduser(m.group(1).strip())))\n"
        "    return out\n"
        "\n"
        "deny_reads = _extract(deny_rules, 'read_file')\n"
        "allow_reads = _extract(allow_rules, 'read_file')\n"
        "allow_writes = _extract(allow_rules, 'write_file')\n"
        "\n"
        "def _within(target, root):\n"
        "    t = os.path.abspath(target)\n"
        "    r = os.path.abspath(root)\n"
        "    return t == r or t.startswith(r.rstrip('/') + '/')\n"
        "\n"
        "def can_read(path_str):\n"
        "    # Exact AGY precedence: deny ALWAYS beats allow\n"
        "    for d in deny_reads:\n"
        "        if _within(path_str, d):\n"
        "            return False, 'Matches user-configured deny rule'\n"
        "    for a in allow_reads + allow_writes:\n"
        "        if _within(path_str, a):\n"
        "            return True, 'allowed'\n"
        "    return False, 'Not in allow list'\n"
        "\n"
        "def can_write(path_str):\n"
        "    for d in deny_reads:\n"
        "        if _within(path_str, d):\n"
        "            return False, 'Matches user-configured deny rule'\n"
        "    for w in allow_writes:\n"
        "        if _within(path_str, w):\n"
        "            return True, 'allowed'\n"
        "    return False, 'Read-only or not in write_file allow list'\n"
        "\n"
        "reg_raw = os.environ.get('AGY_REGISTERED_PLUGINS', '')\n"
        "plugin_root = os.environ.get('AGY_PLUGIN_ROOT', '')\n"
        "result = {\n"
        "    'sandbox_flag': sandbox_flag,\n"
        "    'plugin_root_env': plugin_root,\n"
        "    'registered_plugins_env': reg_raw,\n"
        "    'dont_write_bytecode': os.environ.get('PYTHONDONTWRITEBYTECODE'),\n"
        "    'caller_spoof_check': os.environ.get('CLAUDE_PLUGIN_ROOT'),\n"
        "    'custom_op_flag': os.environ.get('CUSTOM_OP_FLAG'),\n"
        "    'pythonpath_env': os.environ.get('PYTHONPATH'),\n"
        "    'node_options_env': os.environ.get('NODE_OPTIONS'),\n"
        "    'path_env': os.environ.get('PATH'),\n"
        "    'positional_args': positional_args,\n"
        "    'add_dirs': add_dirs,\n"
        "}\n"
        "\n"
        "probe_secret = os.environ.get('MOCK_PROBE_SECRET_PATH', '')\n"
        "if probe_secret:\n"
        "    ok_s, reason_s = can_read(probe_secret)\n"
        "    result['secret_read_allowed'] = ok_s\n"
        "    result['secret_read_reason'] = reason_s\n"
        "\n"
        "if plugin_root:\n"
        "    disc_dir = os.path.join(os.path.expanduser('~'), '.gemini', 'config', 'plugins', 'oh-my-agents')\n"
        "    skill_canon = os.path.join(plugin_root, 'skills', 'spec-to-task', 'SKILL.md')\n"
        "    ok_r, reason_r = can_read(skill_canon)\n"
        "    ok_disc, reason_disc = can_read(os.path.join(disc_dir, 'skills', 'spec-to-task', 'SKILL.md'))\n"
        "    ok_w, reason_w = can_write(skill_canon)\n"
        "    ok_w_disc, _ = can_write(disc_dir)\n"
        "    result['skill_canon_read'] = {'ok': ok_r, 'reason': reason_r}\n"
        "    result['skill_disc_read'] = {'ok': ok_disc, 'reason': reason_disc}\n"
        "    result['plugin_write_allowed'] = ok_w or ok_w_disc\n"
        "    result['plugin_write_reason'] = reason_w\n"
        "    if ok_r and os.path.isfile(skill_canon):\n"
        "        result['skill_content'] = Path(skill_canon).read_text(encoding='utf-8')\n"
        "        hook_proc = subprocess.run(\n"
        "            [sys.executable, './hooks/antigravity-adapter.py', 'SessionStart'],\n"
        "            cwd=plugin_root,\n"
        "            capture_output=True,\n"
        "            text=True,\n"
        "            check=True,\n"
        "        )\n"
        "        result['hook_output'] = json.loads(hook_proc.stdout.strip())\n"
        "\n"
        "    # Execute oh-my-agents /verify write contract inside authorized project workspace\n"
        "    ws = Path(os.getcwd())\n"
        "    ok_ws_w, reason_ws_w = can_write(str(ws / '.claude' / 'signals' / 'verify-latest.json'))\n"
        "    result['workspace_write_allowed'] = ok_ws_w\n"
        "    if ok_ws_w:\n"
        "        sig_p = ws / '.claude' / 'signals' / 'verify-latest.json'\n"
        "        met_p = ws / '.claude' / 'metrics' / 'verify.jsonl'\n"
        "        pln_p = ws / 'docs' / 'exec-plans' / 'active' / 'plan-001.json'\n"
        "        sig_p.parent.mkdir(parents=True, exist_ok=True)\n"
        "        met_p.parent.mkdir(parents=True, exist_ok=True)\n"
        "        pln_p.parent.mkdir(parents=True, exist_ok=True)\n"
        "        sig_p.write_text(json.dumps({'status': 'pass', 'plugin': 'oh-my-agents'}) + '\\n', encoding='utf-8')\n"
        "        met_p.write_text(json.dumps({'checks': 5, 'failed': 0}) + '\\n', encoding='utf-8')\n"
        "        pln_p.write_text(json.dumps({'id': 'plan-001', 'verified': True}) + '\\n', encoding='utf-8')\n"
        "\n"
        "print(json.dumps(result))\n",
        encoding="utf-8",
    )
    os.chmod(bin_path, 0o755)
    return bin_path


class AgyPluginsSecurityAndWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._uid = uuid.uuid4().hex[:10]
        # Dedicated sibling base under real $HOME (outside protected dotfiles, GATEWAY_ROOT, and /tmp)
        home_real = Path(os.path.realpath(str(Path.home())))
        self.plugin_base = home_real / f"dots_test_agy_plugins_{self._uid}"
        self.plugin_base.mkdir(parents=True, exist_ok=True)
        os.chmod(self.plugin_base, 0o755)
        self.plugin_dir = _create_oh_my_agents_fixture(self.plugin_base / "oh-my-agents")

        self.runtime_base = home_real / f"dots_test_agy_rt_{self._uid}"
        self.runtime_base.mkdir(parents=True, exist_ok=True)
        os.chmod(self.runtime_base, 0o755)
        self.workspace_root = self.runtime_base / "workspaces"
        self.project_dir = self.workspace_root / "demo-project"
        self.project_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.workspace_root, 0o755)
        os.chmod(self.project_dir, 0o755)

        self.secrets_dir = self.runtime_base / "gateway-secrets"
        self.secrets_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.secrets_dir, 0o700)

        self.sandbox_dir = self.runtime_base / "sandbox-state"
        self.plugins_reg_file = self.secrets_dir / "agy-plugins.json"
        self.agy_env_file = self.secrets_dir / "agy.env"
        self.codex_env_file = self.secrets_dir / "codex.env"
        self.tunnel_env_file = self.secrets_dir / "tunnel.env"
        self.tunnel_yaml_file = self.secrets_dir / "dots-gateway.yaml"

        self.secret_api_token = f"dots_gw_secret_tok_{self._uid}_998877"
        self.secret_hmac = f"hmac_super_secret_{self._uid}_aabbccdd"
        self.secret_tunnel_key = f"sk-tunnel-runtime-{self._uid}-secretvalue"
        self.secret_codex_key = f"sk-proj-codex-{self._uid}-secretvalue"

        self.tunnel_env_file.write_text(
            f"CONTROL_PLANE_TUNNEL_ID=tunnel_{self._uid}\n"
            f"CONTROL_PLANE_API_KEY={self.secret_tunnel_key}\n"
            f'DOTS_GW_AUTH_HDR="Bearer {self.secret_api_token}"\n',
            encoding="utf-8",
        )
        os.chmod(self.tunnel_env_file, 0o600)
        self.tunnel_yaml_file.write_text(
            f'tunnel_id: "tunnel_{self._uid}"\n', encoding="utf-8"
        )
        os.chmod(self.tunnel_yaml_file, 0o600)
        self.codex_env_file.write_text(
            f"OPENAI_API_KEY={self.secret_codex_key}\n", encoding="utf-8"
        )
        os.chmod(self.codex_env_file, 0o600)
        self.agy_env_file.write_text("export AGY_ADC_AUTH=false\n", encoding="utf-8")
        os.chmod(self.agy_env_file, 0o600)

        self.mock_agy_bin = _create_mock_agy_binary(
            self.plugin_base / "bin" / "agy"
        )

        self.cfg = GatewayConfig(
            host="127.0.0.1",
            port=0,
            api_tokens=[self.secret_api_token],
            users={"dots_op": hash_password_pbkdf2("dots_pass_123")},
            hmac_secret=self.secret_hmac,
            allowed_workdirs=[str(self.workspace_root)],
            default_workdir=str(self.workspace_root),
            protected_paths=[
                str(GATEWAY_ROOT),
                str(self.secrets_dir),
                str(Path.home() / ".ssh"),
                str(Path.home() / ".gnupg"),
                str(Path.home() / ".config" / "dots-gateway"),
                str(Path.home() / ".config" / "tunnel-client"),
                str(Path.home() / ".gemini"),
                str(Path.home() / ".codex"),
            ],
            isolate_mount_namespace=True,
            agy_binary=str(self.mock_agy_bin),
            agy_default_sandbox=True,
            agy_default_skip_permissions=True,
            agy_env_file=str(self.agy_env_file),
            agy_model_file=str(self.secrets_dir / "agy.model"),
            agy_plugins_enabled=False,
            agy_plugin_dirs=[],
            agy_plugins_file=str(self.plugins_reg_file),
            codex_env_file=str(self.codex_env_file),
            sandbox_state_dir=str(self.sandbox_dir),
            sandbox_lock_timeout_seconds=0.35,
            session_state_dir=str(self.secrets_dir / "sessions"),
            docker_mode_file=str(self.secrets_dir / "docker.mode"),
            docker_proxy_socket=str(self.secrets_dir / "docker-proxy.sock"),
        )
        self.server = GatewayServer(self.cfg)
        host, port = await self.server.start()
        self.base_url = f"http://{host}:{port}"
        self.client = DotsGatewayClient(
            base_url=self.base_url, token=self.secret_api_token
        )

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        # Restore permissions in case a fault test removed write/exec bits
        for base in (self.runtime_base, self.plugin_base):
            if base.exists():
                for root, dirs, files in os.walk(base):
                    try:
                        os.chmod(root, 0o700)
                    except OSError:
                        pass
                    for d in dirs:
                        p = os.path.join(root, d)
                        if not os.path.islink(p):
                            try:
                                os.chmod(p, 0o700)
                            except OSError:
                                pass
                    for f in files:
                        p = os.path.join(root, f)
                        if not os.path.islink(p):
                            try:
                                os.chmod(p, 0o600)
                            except OSError:
                                pass
        shutil.rmtree(self.runtime_base, ignore_errors=True)
        shutil.rmtree(self.plugin_base, ignore_errors=True)

    def _write_hot_plugins_registry(self, enabled: bool, dirs: list[str]) -> None:
        payload = {
            "schema_version": 1,
            "enabled": enabled,
            "plugin_dirs": dirs,
        }
        self.plugins_reg_file.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(self.plugins_reg_file, 0o600)

    def _mcp_rpc(self, method: str, params: dict | None = None, req_id: int = 1) -> dict:
        return self.client._request_json(
            "POST",
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params or {},
            },
        )

    async def test_default_off_backward_compatibility(self) -> None:
        pol = self.server.policy
        info = pol.get_agy_plugins_info()
        self.assertFalse(info["enabled"])
        self.assertFalse(info["configured"])
        self.assertTrue(info["valid"])
        self.assertEqual(info["status"], "disabled")
        self.assertEqual(info["plugins"], [])
        self.assertIsNone(info["error"])

        settings = pol.build_agy_sandbox_settings(cwd=str(self.project_dir))
        allow_rules = settings["permissions"]["allow"]
        deny_rules = settings["permissions"]["deny"]
        self.assertFalse(
            any(str(self.plugin_dir) in r for r in allow_rules),
            f"Plugin path leaked into default-off allow rules: {allow_rules}",
        )
        self.assertFalse(
            any(".gemini/config/plugins" in r for r in allow_rules),
            f"Plugin discovery path leaked into default-off allow rules: {allow_rules}",
        )
        # Parent deny rules for gateway & secrets MUST remain intact
        self.assertIn(f"read_file({os.path.abspath(str(self.secrets_dir))})", deny_rules)
        self.assertIn(f"read_file({os.path.abspath(str(GATEWAY_ROOT))})", deny_rules)

        # HTTP /v1/policy and MCP gateway_status expose clear default-off diagnostics
        http_pol = await asyncio.to_thread(self.client.policy)
        self.assertEqual(http_pol["agy_plugins"]["status"], "disabled")
        self.assertFalse(http_pol["agy_plugins"]["enabled"])

        mcp_res = await asyncio.to_thread(
            self._mcp_rpc, "tools/call", {"name": "gateway_status", "arguments": {}}
        )
        mcp_status = json.loads(mcp_res["result"]["content"][0]["text"])
        self.assertEqual(mcp_status["agy_plugins"]["status"], "disabled")

        with patch("gateway.sandbox.can_use_mount_namespace", return_value=True):
            ns_argv = build_mount_ns_argv(
                ["/bin/true"],
                cwd=str(self.project_dir),
                allowed_workdirs=self.cfg.allowed_workdirs,
                protected_paths=self.cfg.protected_paths,
                is_agy=True,
                sandbox_state_dir=str(self.sandbox_dir),
                agy_plugins_enabled=False,
            )
        script = ns_argv[ns_argv.index("-c") + 1]
        self.assertNotIn(str(self.plugin_dir), script)
        self.assertNotIn("oh-my-agents", script)
        for ln in script.splitlines():
            if ".gemini/config/plugins" in ln:
                self.assertNotIn("tmpfs", ln)

    async def test_valid_oh_my_agents_plugin_sync_rules_and_vfs_mounts(self) -> None:
        # Also test versioned directory name mapped via plugin.json["name"] == "oh-my-agents"
        versioned_dir = _create_oh_my_agents_fixture(
            self.plugin_base / "oh-my-agents-a6aad18f", plugin_name="oh-my-agents"
        )
        self._write_hot_plugins_registry(True, [str(versioned_dir)])

        pol = self.server.policy
        validated = pol.validate_agy_plugins(
            cwd=str(self.project_dir), require_mount_ns_check=False
        )
        self.assertEqual(len(validated), 1)
        plg = validated[0]
        self.assertEqual(plg.name, "oh-my-agents")
        self.assertEqual(plg.source_dir, str(versioned_dir))
        self.assertTrue(
            plg.vfs_discovery_dir.endswith("/.gemini/config/plugins/oh-my-agents")
        )

        # Inject a rogue write_file rule for plugin in temporary settings.json if present;
        # verify build_agy_sandbox_settings strips write_file on plugin paths!
        settings = pol.build_agy_sandbox_settings(cwd=str(self.project_dir))
        allow_rules = settings["permissions"]["allow"]
        deny_rules = settings["permissions"]["deny"]
        self.assertIn(f"read_file({plg.source_dir})", allow_rules)
        self.assertIn(f"read_file({plg.vfs_discovery_dir})", allow_rules)
        self.assertFalse(
            any(
                r.startswith("write_file(")
                and (plg.source_dir in r or plg.vfs_discovery_dir in r)
                for r in allow_rules
            )
        )
        # Protected secret deny rules remain untouched (never deleted or weakened)
        self.assertIn(f"read_file({os.path.abspath(str(self.secrets_dir))})", deny_rules)

        # Verify VFS script mounts isolated tmpfs + read-only binds at both source_dir and vfs_discovery_dir
        with patch("gateway.sandbox.can_use_mount_namespace", return_value=True):
            ns_argv = build_mount_ns_argv(
                [str(self.mock_agy_bin), "--sandbox"],
                cwd=str(self.project_dir),
                allowed_workdirs=self.cfg.allowed_workdirs,
                protected_paths=self.cfg.protected_paths,
                is_agy=True,
                sandbox_state_dir=str(self.sandbox_dir),
                agy_plugins_enabled=True,
                agy_plugin_mounts=[(plg.name, plg.source_dir)],
                masked_plugin_paths=pol.get_configured_agy_plugin_paths(),
                sandbox_lock_timeout_seconds=0.35,
            )
        script = ns_argv[ns_argv.index("-c") + 1]
        self.assertIn("tmpfs", script)
        self.assertIn(".gemini/config/plugins/oh-my-agents", script)
        self.assertIn(str(versioned_dir), script)
        self.assertIn(f"[ ! -L {versioned_dir} ] && [ -d {versioned_dir} ]", script)
        self.assertIn("remount,bind,ro", script)
        # Ensure plugin mount lines never swallow failures with '|| true'
        for ln in script.splitlines():
            if str(versioned_dir) in ln or ".gemini/config/plugins" in ln:
                self.assertNotIn("|| true", ln)

        # Verify /opt plugin path masking on non-AGY sessions (`exec_command` / `run_codex`)
        with patch("gateway.sandbox.can_use_mount_namespace", return_value=True):
            exec_ns_argv = build_mount_ns_argv(
                ["/bin/echo", "hi"],
                cwd=str(self.project_dir),
                allowed_workdirs=self.cfg.allowed_workdirs,
                protected_paths=self.cfg.protected_paths,
                is_agy=False,
                sandbox_state_dir=str(self.sandbox_dir),
                agy_plugins_enabled=False,
                masked_plugin_paths=["/opt/agy-plugins/oh-my-agents"],
            )
        exec_script = exec_ns_argv[exec_ns_argv.index("-c") + 1]
        self.assertIn("/opt/agy-plugins/oh-my-agents", exec_script)
        self.assertIn("mode=0555,ro tmpfs", exec_script)

    async def test_three_category_overlap_and_symlink_escape_rejections(self) -> None:
        # 1. Mixed umbrella parent directory (exact root cause from problem statement!):
        # Put plugin and secret under a shared protected umbrella dir -> MUST fail closed with clear message
        umbrella = self.runtime_base / "mixed-umbrella"
        umbrella_secret = umbrella / "tunnel-creds"
        umbrella_secret.mkdir(parents=True)
        umbrella_plugin = _create_oh_my_agents_fixture(umbrella / "oh-my-agents")

        mixed_cfg = GatewayConfig(
            allowed_workdirs=[str(self.workspace_root)],
            default_workdir=str(self.workspace_root),
            protected_paths=[str(umbrella)],
            sandbox_state_dir=str(self.sandbox_dir),
            agy_plugins_enabled=True,
            agy_plugin_dirs=[str(umbrella_plugin)],
            agy_plugins_file=str(self.secrets_dir / "none.json"),
        )
        mixed_pol = CommandPolicy(mixed_cfg)
        with self.assertRaises(PermissionError) as umbrella_err:
            mixed_pol.validate_agy_plugins(require_mount_ns_check=False)
        self.assertIn("overlaps protected", str(umbrella_err.exception))

        # 2. Plugin inside GATEWAY_ROOT, secrets_dir, allowed_workdirs, sandbox_state_dir, or /tmp
        ws_plugin = _create_oh_my_agents_fixture(self.workspace_root / "ws-plugin")
        sb_plugin = _create_oh_my_agents_fixture(self.sandbox_dir / "sb-plugin")
        sec_plugin = _create_oh_my_agents_fixture(self.secrets_dir / "sec-plugin")
        tmp_plugin = Path(tempfile.mkdtemp(prefix="dots_bad_tmp_plg_"))
        try:
            _create_oh_my_agents_fixture(tmp_plugin / "oh-my-agents")
            bad_cases = [
                (str(ws_plugin), "overlaps writable"),
                (str(self.workspace_root), "overlaps writable"),
                (str(sb_plugin), "overlaps writable"),
                (str(sec_plugin), "overlaps protected"),
                (str(GATEWAY_ROOT), "overlaps protected"),
                (str(Path.home()), "HOME root"),
                (str(tmp_plugin / "oh-my-agents"), "forbidden system/temp"),
            ]
            for bad_path, expected_substr in bad_cases:
                self._write_hot_plugins_registry(True, [bad_path])
                with self.assertRaises(PermissionError, msg=f"Expected failure for {bad_path}") as ctx:
                    self.server.policy.validate_agy_plugins(require_mount_ns_check=False)
                self.assertIn(expected_substr, str(ctx.exception))
        finally:
            shutil.rmtree(tmp_plugin, ignore_errors=True)

        # 3. Symlinked plugin root & symlinked parent traversal
        sym_root = self.plugin_base / "symlink-oh-my-agents"
        os.symlink(self.plugin_dir, sym_root)
        self._write_hot_plugins_registry(True, [str(sym_root)])
        with self.assertRaises(PermissionError) as sym_err:
            self.server.policy.validate_agy_plugins(require_mount_ns_check=False)
        self.assertIn("symlink", str(sym_err.exception).lower())

        sym_parent = self.plugin_base / "sym-parent"
        os.symlink(self.plugin_base, sym_parent)
        self._write_hot_plugins_registry(True, [str(sym_parent / "oh-my-agents")])
        with self.assertRaises(PermissionError) as sym_parent_err:
            self.server.policy.validate_agy_plugins(require_mount_ns_check=False)
        self.assertIn("symlink", str(sym_parent_err.exception).lower())

        # 4. Internal symlink escaping plugin root to tunnel.env
        esc_plugin = _create_oh_my_agents_fixture(self.plugin_base / "escape-plugin")
        os.symlink(self.tunnel_env_file, esc_plugin / "skills" / "leaked-tunnel.env")
        self._write_hot_plugins_registry(True, [str(esc_plugin)])
        with self.assertRaises(PermissionError) as esc_err:
            self.server.policy.validate_agy_plugins(require_mount_ns_check=False)
        self.assertIn("escapes", str(esc_err.exception))

        # 5. Dangling symlink inside plugin
        (esc_plugin / "skills" / "leaked-tunnel.env").unlink()
        os.symlink(esc_plugin / "does-not-exist", esc_plugin / "skills" / "dangling.md")
        with self.assertRaises(PermissionError) as dang_err:
            self.server.policy.validate_agy_plugins(require_mount_ns_check=False)
        self.assertIn("Dangling symlink", str(dang_err.exception))
        (esc_plugin / "skills" / "dangling.md").unlink()

        # 6. World-writable file inside plugin
        ww_file = esc_plugin / "skills" / "world_writable.md"
        ww_file.write_text("bad\n", encoding="utf-8")
        os.chmod(ww_file, 0o666)
        with self.assertRaises(PermissionError) as ww_err:
            self.server.policy.validate_agy_plugins(require_mount_ns_check=False)
        self.assertIn("World-writable", str(ww_err.exception))
        ww_file.unlink()

        # 7. FIFO special file inside plugin
        fifo_p = esc_plugin / "skills" / "bad.fifo"
        os.mkfifo(fifo_p)
        with self.assertRaises(PermissionError) as fifo_err:
            self.server.policy.validate_agy_plugins(require_mount_ns_check=False)
        self.assertIn("Special device/socket/FIFO", str(fifo_err.exception))
        fifo_p.unlink()

        # 8. Corrupted or world-writable agy-plugins.json fails closed, while GET /v1/policy stays HTTP 200
        self.plugins_reg_file.write_text("{corrupt-json", encoding="utf-8")
        os.chmod(self.plugins_reg_file, 0o600)
        pol_diag = await asyncio.to_thread(self.client.policy)
        self.assertFalse(pol_diag["agy_plugins"]["valid"])
        self.assertEqual(pol_diag["agy_plugins"]["status"], "error")
        with self.assertRaises(RuntimeError) as agy_403:
            await asyncio.to_thread(
                self.client._request_json,
                "POST",
                "/v1/agy",
                {"prompt": "hi", "cwd": str(self.project_dir)},
            )
        self.assertIn("403", str(agy_403.exception))

        # 9. isolate_mount_namespace=False or agy_default_sandbox=False or --no-sandbox MUST fail closed
        for bad_kwargs in (
            {"isolate_mount_namespace": False},
            {"agy_default_sandbox": False},
        ):
            bad_cfg = GatewayConfig(
                allowed_workdirs=[str(self.workspace_root)],
                default_workdir=str(self.workspace_root),
                sandbox_state_dir=str(self.sandbox_dir),
                agy_binary=str(self.mock_agy_bin),
                agy_plugins_enabled=True,
                agy_plugin_dirs=[str(self.plugin_dir)],
                agy_plugins_file=str(self.secrets_dir / "none.json"),
                **bad_kwargs,
            )
            with self.assertRaises(PermissionError):
                CommandPolicy(bad_cfg).validate_agy_plugins(require_mount_ns_check=False)

        self._write_hot_plugins_registry(True, [str(self.plugin_dir)])
        with self.assertRaises(PermissionError):
            self.server.policy.build_agy_argv(
                prompt="test", cwd=str(self.project_dir), sandbox=False
            )

        # 10. When can_use_mount_namespace() is False, require_mount_ns_check=True fails closed
        with patch("gateway.policy.can_use_mount_namespace", return_value=False):
            with self.assertRaises(PermissionError) as mns_err:
                self.server.policy.validate_agy_plugins(require_mount_ns_check=True)
            self.assertIn("mount namespaces", str(mns_err.exception))

    async def test_task_escalation_and_other_entrypoints_no_regression(self) -> None:
        self._write_hot_plugins_registry(True, [str(self.plugin_dir)])
        skill_file = self.plugin_dir / "skills" / "spec-to-task" / "SKILL.md"

        # 1. Task-level plugin keys in HTTP /v1/agy, /v1/exec, /v1/codex, /v1/sessions -> 403
        for route, payload in (
            ("/v1/agy", {"prompt": "hi", "cwd": str(self.project_dir), "plugin_dirs": [str(self.plugin_dir)]}),
            ("/v1/agy", {"prompt": "hi", "cwd": str(self.project_dir), "agy_plugin_dirs": [str(self.plugin_dir)]}),
            ("/v1/agy", {"prompt": "hi", "cwd": str(self.project_dir), "plugins": ["oh-my-agents"]}),
            ("/v1/agy", {"prompt": "hi", "cwd": str(self.project_dir), "plugin_root": str(self.plugin_dir)}),
            ("/v1/exec", {"command": "pwd", "cwd": str(self.project_dir), "plugin_dirs": [str(self.plugin_dir)]}),
            ("/v1/codex", {"prompt": "hi", "cwd": str(self.project_dir), "plugin_dirs": [str(self.plugin_dir)]}),
            ("/v1/sessions", {"type": "agy", "cwd": str(self.project_dir), "plugin_dirs": [str(self.plugin_dir)]}),
        ):
            with self.assertRaises(RuntimeError, msg=f"Route {route} must reject {payload}") as exc_ctx:
                await asyncio.to_thread(self.client._request_json, "POST", route, payload)
            self.assertIn("403", str(exc_ctx.exception))

        # 2. Task-level plugin keys in MCP tools -> isError=True
        for tool_name, tool_args in (
            ("run_agy", {"prompt": "hi", "cwd": str(self.project_dir), "plugin_dirs": [str(self.plugin_dir)]}),
            ("exec_command", {"command": "pwd", "cwd": str(self.project_dir), "plugins": ["x"]}),
            ("run_codex", {"prompt": "hi", "cwd": str(self.project_dir), "agy_plugin_dirs": ["x"]}),
            ("session_start", {"type": "agy", "cwd": str(self.project_dir), "plugin_root": "x"}),
        ):
            res = await asyncio.to_thread(
                self._mcp_rpc, "tools/call", {"name": tool_name, "arguments": tool_args}
            )
            self.assertTrue(res["result"].get("isError"), f"{tool_name} must fail on plugin override")

        # 3. CLI flags --plugin-dir / --plugin / `agy plugin install` in args or exec_command -> 403
        for bad_args in (
            ["--plugin-dir", str(self.project_dir)],
            [f"--plugin-dir={self.project_dir}"],
            ["--plugin", "evil"],
            ["plugin", "install", "evil"],
        ):
            with self.assertRaises(RuntimeError) as arg_err:
                await asyncio.to_thread(
                    self.client._request_json,
                    "POST",
                    "/v1/agy",
                    {"prompt": "hi", "cwd": str(self.project_dir), "args": bad_args},
                )
            self.assertIn("403", str(arg_err.exception))

        # 4. File API (/v1/files/* and MCP fs_*) MUST NOT gain read/write/list/delete on plugin paths
        for file_route, method, body in (
            (f"/v1/files/read?path={skill_file}", "GET", None),
            (f"/v1/files/list?path={self.plugin_dir}", "GET", None),
            (f"/v1/files/stat?path={skill_file}", "GET", None),
            ("/v1/files/write", "POST", {"path": str(self.plugin_dir / "pwn.txt"), "content": "x"}),
            ("/v1/files/delete", "POST", {"path": str(skill_file)}),
        ):
            with self.assertRaises(RuntimeError, msg=f"File API {file_route} must deny plugin path") as f_err:
                await asyncio.to_thread(self.client._request_json, method, file_route, body)
            self.assertIn("403", str(f_err.exception))

        mcp_fs_read = await asyncio.to_thread(
            self._mcp_rpc, "tools/call", {"name": "fs_read", "arguments": {"path": str(skill_file)}}
        )
        self.assertTrue(mcp_fs_read["result"].get("isError"))

        # Normal workspace File API operations have ZERO regression
        ws_hello = self.project_dir / "hello.txt"
        await asyncio.to_thread(
            self.client._request_json,
            "POST",
            "/v1/files/write",
            {"path": str(ws_hello), "content": "workspace-ok\n"},
        )
        read_back = await asyncio.to_thread(
            self.client._request_json, "GET", f"/v1/files/read?path={ws_hello}", None
        )
        self.assertEqual(read_back["content"], "workspace-ok\n")

        # 5. exec_command and run_codex CANNOT access or mount registered plugin paths
        dec_cmd = self.server.policy.validate_command(
            f"cat {skill_file}", cwd=str(self.project_dir)
        )
        self.assertFalse(
            dec_cmd.allowed, f"exec_command must block reading plugin path: {dec_cmd.reason}"
        )

        dec_hook_exec = self.server.policy.validate_command(
            f"{self.plugin_dir}/hooks/antigravity-adapter.py", cwd=str(self.project_dir)
        )
        self.assertFalse(dec_hook_exec.allowed)

        with self.assertRaises(PermissionError):
            self.server.policy.build_codex_argv(
                prompt="review", cwd=str(self.project_dir), add_dirs=[str(self.plugin_dir)]
            )
        self.assertFalse(
            any(
                str(self.plugin_dir) in p
                for p in self.server.policy.get_codex_writable_roots(cwd=str(self.project_dir))
            )
        )

        # 6. DockerProxy policy MUST reject bind mounts targeting registered plugin directories
        docker_pol = DockerRequestPolicy(self.cfg, self.server.policy)
        with self.assertRaises(DockerPolicyError) as dp_err1:
            docker_pol.check_host_path(str(self.plugin_dir), what="bind")
        self.assertIn("AGY-only plugin", str(dp_err1.exception))
        with self.assertRaises(DockerPolicyError):
            docker_pol.check_host_path(str(skill_file), what="bind")
        # Authorized workspace bind mount still works without regression
        self.assertIsNone(docker_pol.check_host_path(str(self.project_dir), what="bind"))

    async def test_end_to_end_agy_plugin_workflow_and_zero_restart_rollback(self) -> None:
        self._write_hot_plugins_registry(True, [str(self.plugin_dir)])
        before_snap = _snapshot_tree(self.plugin_dir)

        # On hosts with real unshare (e.g. local-gateway), run full kernel VFS namespace;
        # inside a container seccomp sandbox, validate VFS builder arguments & run mock agy directly.
        real_mns = can_use_mount_namespace()
        captured_ns_calls: list[dict] = []

        def _passthrough_mount_ns(target_argv, **kwargs):
            import shlex as _shlex

            captured_ns_calls.append({"target_argv": list(target_argv), **kwargs})
            if kwargs.get("is_agy") and kwargs.get("agy_plugins_enabled"):
                from gateway.sandbox import _validate_plugin_mounts_for_vfs

                _validate_plugin_mounts_for_vfs(kwargs.get("agy_plugin_mounts"))
            prepare_sandbox_runtime_state(
                kwargs.get("sandbox_state_dir") or str(self.sandbox_dir),
                lock_timeout_seconds=kwargs.get("sandbox_lock_timeout_seconds", 0.35),
                forbidden_roots=kwargs.get("masked_plugin_paths") or (),
            )
            target_cwd = kwargs.get("cwd") or str(self.project_dir)
            return [
                "/bin/bash",
                "-c",
                f"cd {_shlex.quote(str(target_cwd))} && exec \"$@\"",
                "--",
                *target_argv,
            ]

        ctx_patches = (
            []
            if real_mns
            else [
                patch("gateway.policy.can_use_mount_namespace", return_value=True),
                patch("gateway.executor.build_mount_ns_argv", side_effect=_passthrough_mount_ns),
            ]
        )

        for p in ctx_patches:
            p.start()
        try:
            # 1. HTTP POST /v1/agy with caller env attempting to spoof AGY_PLUGIN_ROOT & CLAUDE_PLUGIN_ROOT
            resp = await asyncio.to_thread(
                self.client._request_json,
                "POST",
                "/v1/agy",
                {
                    "prompt": "Run spec-to-task and verify workflow",
                    "cwd": str(self.project_dir),
                    "env": {
                        "AGY_PLUGIN_ROOT": "/evil/spoofed/root",
                        "CLAUDE_PLUGIN_ROOT": "/evil/claude/root",
                        "HOME": "/evil/home",
                        "TMPDIR": str(self.plugin_dir),
                        "MOCK_PROBE_SECRET_PATH": str(self.tunnel_env_file),
                    },
                },
            )
            self.assertTrue(resp["ok"], f"run_agy failed: {resp}")
            out_data = json.loads(resp["stdout"].strip())

            # Plugin discovered & spec-to-task/SKILL.md read without 'Matches user-configured deny rule'!
            self.assertFalse(out_data["sandbox_flag"])
            self.assertEqual(out_data["plugin_root_env"], str(self.plugin_dir))
            self.assertEqual(out_data["dont_write_bytecode"], "1")
            self.assertIsNone(out_data["caller_spoof_check"])
            self.assertTrue(out_data["skill_canon_read"]["ok"])
            self.assertTrue(out_data["skill_disc_read"]["ok"])
            self.assertIn("SPEC_TO_TASK_SENTINEL_OK", out_data["skill_content"])
            self.assertEqual(out_data["hook_output"]["hook_event"], "SessionStart")
            self.assertEqual(out_data["hook_output"]["dont_write_bytecode"], "1")
            self.assertFalse(
                out_data["hook_output"]["tmp_used"].startswith(str(self.plugin_dir)),
                "Hook tempfile must never write inside plugin directory",
            )

            # Plugin is NOT writable in rules, and tunnel secret remains blocked by deny rule!
            self.assertFalse(out_data["plugin_write_allowed"])
            self.assertFalse(out_data["secret_read_allowed"])
            self.assertEqual(
                out_data["secret_read_reason"], "Matches user-configured deny rule"
            )

            # Project workspace /verify artifacts written cleanly
            self.assertTrue(out_data["workspace_write_allowed"])
            self.assertTrue(
                (self.project_dir / ".claude" / "signals" / "verify-latest.json").is_file()
            )
            self.assertTrue(
                (self.project_dir / ".claude" / "metrics" / "verify.jsonl").is_file()
            )
            self.assertTrue(
                (self.project_dir / "docs" / "exec-plans" / "active" / "plan-001.json").is_file()
            )

            # Plugin directory tree (files, modes, hashes, no __pycache__) is 100% untouched!
            after_snap = _snapshot_tree(self.plugin_dir)
            self.assertEqual(before_snap, after_snap)

            # 2. MCP tools/call `run_agy` also works end-to-end
            mcp_agy = await asyncio.to_thread(
                self._mcp_rpc,
                "tools/call",
                {
                    "name": "run_agy",
                    "arguments": {
                        "prompt": "Verify via MCP",
                        "cwd": str(self.project_dir),
                    },
                },
            )
            self.assertFalse(mcp_agy["result"].get("isError"), f"MCP run_agy error: {mcp_agy}")
            self.assertIn("SPEC_TO_TASK_SENTINEL_OK", mcp_agy["result"]["content"][0]["text"])

            # 2b. WebSocket `/v1/ws` rejects task-level `plugin_dirs` and runs registered AGY plugin flow
            async with DotsWebSocketSession(self.client) as ws:
                await ws.send_json(
                    {
                        "action": "agy",
                        "prompt": "Spoof via WS",
                        "cwd": str(self.project_dir),
                        "plugin_dirs": [str(self.plugin_dir)],
                    }
                )
                ws_err = await asyncio.wait_for(ws.recv_json(), timeout=5.0)
                self.assertIsNotNone(ws_err)
                self.assertEqual(ws_err["type"], "error")
                self.assertIn("plugin_dirs", str(ws_err.get("error", "")))

                await ws.send_json(
                    {
                        "action": "agy",
                        "prompt": "Verify via WS",
                        "cwd": str(self.project_dir),
                    }
                )
                ws_chunks: list[str] = []
                ws_exit_code: int | None = None
                while True:
                    frame = await asyncio.wait_for(ws.recv_json(), timeout=10.0)
                    self.assertIsNotNone(frame)
                    if frame["type"] == "session.event":
                        ev = frame.get("event") or {}
                        if ev.get("type") == "stdout":
                            ws_chunks.append(str(ev.get("data", "")))
                        elif ev.get("type") == "exit":
                            ws_exit_code = int((ev.get("data") or {}).get("returncode", -1))
                            break
                    elif frame["type"] == "error":
                        self.fail(f"Unexpected WS error frame: {frame}")
                self.assertEqual(ws_exit_code, 0)
                self.assertIn("SPEC_TO_TASK_SENTINEL_OK", "".join(ws_chunks))

            # 3. Instant Zero-Restart Rollback: flip enabled=False in agy-plugins.json
            self._write_hot_plugins_registry(False, [str(self.plugin_dir)])
            rb_resp = await asyncio.to_thread(
                self.client._request_json,
                "POST",
                "/v1/agy",
                {"prompt": "After rollback", "cwd": str(self.project_dir)},
            )
            self.assertTrue(rb_resp["ok"])
            rb_data = json.loads(rb_resp["stdout"].strip())
            self.assertEqual(rb_data["plugin_root_env"], "")
            self.assertEqual(rb_data["registered_plugins_env"], "")
            if not real_mns:
                self.assertFalse(captured_ns_calls[-1]["agy_plugins_enabled"])
                self.assertIn(
                    str(self.plugin_dir), captured_ns_calls[-1]["masked_plugin_paths"]
                )
        finally:
            for p in reversed(ctx_patches):
                p.stop()

    async def test_sandbox_lock_timeout_unwritable_dir_and_disk_faults(self) -> None:
        home_plugin_before = _snapshot_tree(self.plugin_dir)

        # 1. Lock timeout on .sandbox-init.lock -> SandboxLockTimeoutError -> HTTP 503
        prepare_sandbox_runtime_state(str(self.sandbox_dir), lock_timeout_seconds=0.3)
        lock_file = self.sandbox_dir / ".sandbox-init.lock"
        held_fd = os.open(str(lock_file), os.O_RDWR)
        try:
            fcntl.flock(held_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(SandboxLockTimeoutError):
                prepare_sandbox_runtime_state(
                    str(self.sandbox_dir), lock_timeout_seconds=0.12
                )

            with self.assertRaises(RuntimeError) as http_503:
                await asyncio.to_thread(
                    self.client._request_json,
                    "POST",
                    "/v1/exec",
                    {"command": "echo should_not_run", "cwd": str(self.project_dir)},
                )
            self.assertIn("503", str(http_503.exception))
            self.assertIn("Timed out", str(http_503.exception))

            mcp_lock_err = await asyncio.to_thread(
                self._mcp_rpc,
                "tools/call",
                {
                    "name": "exec_command",
                    "arguments": {"command": "echo no", "cwd": str(self.project_dir)},
                },
            )
            self.assertTrue(mcp_lock_err["result"].get("isError"))
        finally:
            fcntl.flock(held_fd, fcntl.LOCK_UN)
            os.close(held_fd)

        # 2. sandbox_state_dir overlapping plugin directory or HOME root -> explicit SandboxStorageError
        with self.assertRaises(SandboxStorageError):
            prepare_sandbox_runtime_state(
                str(self.plugin_dir / "sub-cache"),
                forbidden_roots=[str(self.plugin_dir)],
            )
        with self.assertRaises(SandboxStorageError):
            prepare_sandbox_runtime_state(str(Path.home()))

        # 3. Non-writable tmp subdir (`chmod 0500`) -> explicit SandboxStorageError (EACCES)
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            os.chmod(self.sandbox_dir / "tmp", 0o500)
            try:
                with self.assertRaises(SandboxStorageError) as perm_err:
                    prepare_sandbox_runtime_state(
                        str(self.sandbox_dir), lock_timeout_seconds=0.2
                    )
                self.assertIn("tmp", str(perm_err.exception))
            finally:
                os.chmod(self.sandbox_dir / "tmp", 0o700)

        # 4. Simulated disk faults (ENOSPC, EROFS, EIO) -> explicit SandboxStorageError & HTTP 503
        for fault_errno, fault_name in (
            (errno.ENOSPC, "ENOSPC"),
            (errno.EROFS, "EROFS"),
            (errno.EIO, "EIO"),
        ):
            with patch(
                "gateway.sandbox.os.write",
                side_effect=OSError(fault_errno, f"Simulated {fault_name}"),
            ):
                with self.assertRaises(SandboxStorageError) as disk_err:
                    prepare_sandbox_runtime_state(
                        str(self.sandbox_dir), lock_timeout_seconds=0.2
                    )
                self.assertIn(fault_name, str(disk_err.exception))

                with self.assertRaises(RuntimeError) as disk_503:
                    await asyncio.to_thread(
                        self.client._request_json,
                        "POST",
                        "/v1/exec",
                        {"command": "pwd", "cwd": str(self.project_dir)},
                    )
                self.assertIn("503", str(disk_503.exception))

        # Verify plugin directory remained completely untouched across all storage failures
        self.assertEqual(home_plugin_before, _snapshot_tree(self.plugin_dir))

    async def test_secret_redaction_and_gateway_sh_cli_lifecycle(self) -> None:
        # 1. Verify redact_diagnostic_text scrubs gateway tokens, HMAC secret, tunnel key, and codex key
        leaked_msg = (
            f"Failure near api_token={self.secret_api_token} "
            f"hmac={self.secret_hmac} "
            f"CONTROL_PLANE_API_KEY={self.secret_tunnel_key} "
            f"Bearer {self.secret_api_token} "
            f"codex={self.secret_codex_key}"
        )
        scrubbed = redact_diagnostic_text(
            leaked_msg,
            self.cfg,
            extra_secrets=[self.secret_tunnel_key],
        )
        for secret_val in (
            self.secret_api_token,
            self.secret_hmac,
            self.secret_tunnel_key,
            self.secret_codex_key,
        ):
            self.assertNotIn(secret_val, scrubbed)
        self.assertIn("[REDACTED]", scrubbed)

        # Even if an operator accidentally puts a secret string in agy_plugin_dirs,
        # /v1/policy and HTTP error responses MUST scrub it!
        bad_secret_path = f"/nonexistent/{self.secret_api_token}/{self.secret_hmac}"
        self._write_hot_plugins_registry(True, [bad_secret_path])
        pol_resp = await asyncio.to_thread(self.client.policy)
        pol_dump = json.dumps(pol_resp)
        self.assertNotIn(self.secret_api_token, pol_dump)
        self.assertNotIn(self.secret_hmac, pol_dump)

        with self.assertRaises(RuntimeError) as err_403:
            await asyncio.to_thread(
                self.client._request_json,
                "POST",
                "/v1/agy",
                {"prompt": "hi", "cwd": str(self.project_dir)},
            )
        self.assertNotIn(self.secret_api_token, str(err_403.exception))
        self.assertNotIn(self.secret_hmac, str(err_403.exception))

        # 2. Test `./gateway.sh agy-plugins` operator CLI lifecycle hermetically
        cli_cfg_file = self.secrets_dir / "cli-config.json"
        cli_reg_file = self.secrets_dir / "cli-agy-plugins.json"
        cli_cfg_file.write_text(
            json.dumps(
                {
                    "allowed_workdirs": [str(self.workspace_root)],
                    "default_workdir": str(self.workspace_root),
                    "protected_paths": self.cfg.protected_paths,
                    "sandbox_state_dir": str(self.sandbox_dir),
                    "agy_plugins_enabled": False,
                    "agy_plugin_dirs": [],
                    "agy_plugins_file": str(cli_reg_file),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        cli_env = {
            **os.environ,
            "GATEWAY_CONFIG_FILE": str(cli_cfg_file),
            "GATEWAY_CLIENT_CONFIG_DIR": str(self.secrets_dir),
            "GATEWAY_AGY_PLUGINS_FILE": str(cli_reg_file),
        }
        gw_sh = str(GATEWAY_ROOT / "gateway.sh")

        def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", gw_sh, "agy-plugins", *args],
                cwd=str(GATEWAY_ROOT),
                env=cli_env,
                capture_output=True,
                text=True,
                timeout=15,
            )

        # Default status: disabled
        r_st0 = _run_cli("status")
        self.assertEqual(r_st0.returncode, 0, r_st0.stderr)
        self.assertIn("disabled", r_st0.stdout)

        # `on` before `add` MUST fail closed
        r_on_empty = _run_cli("on")
        self.assertNotEqual(r_on_empty.returncode, 0)

        # `add` unsafe overlapping workspace path MUST fail closed without creating registry file
        r_add_bad = _run_cli("add", str(self.workspace_root))
        self.assertNotEqual(r_add_bad.returncode, 0)
        self.assertFalse(cli_reg_file.exists())

        # `add` valid separated plugin -> succeeds (staged, still disabled until `on`)
        r_add_ok = _run_cli("add", str(self.plugin_dir))
        self.assertEqual(r_add_ok.returncode, 0, r_add_ok.stderr)
        st_after_add = json.loads(cli_reg_file.read_text(encoding="utf-8"))
        self.assertFalse(st_after_add["enabled"])
        self.assertEqual(st_after_add["plugin_dirs"], [str(self.plugin_dir)])
        self.assertEqual(stat.S_IMODE(cli_reg_file.stat().st_mode), 0o600)

        # `on` -> enables hot-reload
        r_on = _run_cli("on")
        self.assertEqual(r_on.returncode, 0, r_on.stderr)
        self.assertTrue(json.loads(cli_reg_file.read_text(encoding="utf-8"))["enabled"])

        # `doctor` -> validates config, sandbox lock/tmp probe, 3-tier boundaries, and --settings rules
        r_doc = _run_cli("doctor")
        self.assertEqual(r_doc.returncode, 0, f"stdout={r_doc.stdout}\nstderr={r_doc.stderr}")
        self.assertIn("[3/4]", r_doc.stdout)

        # `off` -> instant zero-restart rollback
        r_off = _run_cli("off")
        self.assertEqual(r_off.returncode, 0, r_off.stderr)
        self.assertFalse(json.loads(cli_reg_file.read_text(encoding="utf-8"))["enabled"])

        # `remove` & `clear`
        r_rm = _run_cli("remove", str(self.plugin_dir))
        self.assertEqual(r_rm.returncode, 0, r_rm.stderr)
        self.assertEqual(
            json.loads(cli_reg_file.read_text(encoding="utf-8"))["plugin_dirs"], []
        )

        r_clr = _run_cli("clear")
        self.assertEqual(r_clr.returncode, 0, r_clr.stderr)
        self.assertFalse(cli_reg_file.exists())

    async def test_adversarial_review_hardening_regressions(self) -> None:
        self._write_hot_plugins_registry(True, [str(self.plugin_dir)])
        pol = self.server.policy

        # --- CRITICAL-1: Positional prompt `--settings=...` injection & duplicate `--settings` ---
        evil_prompt = '--settings={"permissions":{"allow":["read_file(/)"],"deny":[]}}'
        argv_no_print = pol.build_agy_argv(
            prompt=evil_prompt, print_mode=False, cwd=str(self.project_dir)
        )
        self.assertIn("--", argv_no_print)
        dd_idx = argv_no_print.index("--")
        self.assertEqual(argv_no_print[dd_idx + 1], evil_prompt)
        # Only the single gateway-synthesized --settings={...} appears before '--'
        self.assertEqual(
            sum(1 for tok in argv_no_print[:dd_idx] if tok.startswith("--settings=")),
            1,
        )

        # Combining `prompt` with `-p`/`--print`, passing `--` in `args`, or dangling value-taking flags MUST fail closed
        for bad_extra_args, pm in (
            (["-p", "real_prompt"], True),
            (["--model", "--", "-p", "hi"], True),
            (["--", "extra"], False),
            (["--model"], False),
            (["--model"], True),
            (["--unknown-dangling-flag"], False),
            ([evil_prompt], True),
        ):
            with self.assertRaises(
                PermissionError, msg=f"Expected rejection for args={bad_extra_args!r}"
            ):
                pol.build_agy_argv(
                    prompt=evil_prompt,
                    args=bad_extra_args,
                    print_mode=pm,
                    cwd=str(self.project_dir),
                )

        # Direct `validate_command` with two `--settings={` tokens or non-terminal `--` MUST fail closed
        for bad_trusted_argv in (
            [
                str(self.mock_agy_bin),
                "--sandbox",
                '--settings={"permissions":{"deny":["read_file(/etc)"]}}',
                evil_prompt,
            ],
            [
                str(self.mock_agy_bin),
                "--sandbox",
                '--settings={"permissions":{"deny":["read_file(/etc)"]}}',
                "--model",
                "--",
                evil_prompt,
            ],
        ):
            bad_dec = pol.validate_command(
                bad_trusted_argv, cwd=str(self.project_dir), _trusted_agy_argv=True
            )
            self.assertFalse(bad_dec.allowed, bad_dec.reason)

        # --- HIGH-1 & RESIDUAL-2: exec_command blocks direct/wrapped/symlinked agy & codex and protected shell env overrides ---
        ws_agy_alias = self.project_dir / "my_agy_runner"
        os.symlink(self.mock_agy_bin, ws_agy_alias)
        try:
            blocked_exec_cmds = [
                f"{self.mock_agy_bin} --help",
                "./my_agy_runner --help",
                f"{ws_agy_alias} --help",
                "agy --help",
                "codex exec hi",
                f"env {self.mock_agy_bin} --help",
                "timeout 5 agy --help",
                "nohup codex exec hi",
                "time agy --help",
                "echo hi | xargs agy --help",
                "echo hi | xargs -n 1 ./my_agy_runner --help",
                f"echo hi | xargs cat {self.tunnel_env_file}",
                f"env cat {self.tunnel_env_file}",
                f"timeout 5 cat {self.plugin_dir / 'plugin.json'}",
                "PATH=/tmp ls",
                "PYTHONPATH=/tmp python3 -V",
                "LD_PRELOAD=/tmp/evil.so ls",
                "NODE_OPTIONS=--require=/tmp/x.js pwd",
                "export AGY_PLUGIN_ROOT=/tmp && pwd",
                "unset TMPDIR && pwd",
                "env HOME=/tmp pwd",
                "GATEWAY_SECRET_OVERRIDE=1 pwd",
            ]
            for bad_cmd in blocked_exec_cmds:
                dec = pol.validate_command(bad_cmd, cwd=str(self.project_dir))
                self.assertFalse(
                    dec.allowed, f"Expected exec_command to reject: {bad_cmd!r}"
                )
        finally:
            ws_agy_alias.unlink(missing_ok=True)

        # Harmless local variable assignment and benign xargs in exec_command still work without regression
        for ok_cmd in ("APP_ENV=staging echo ok", "echo hi | xargs", "echo hi | xargs echo"):
            harmless_dec = pol.validate_command(ok_cmd, cwd=str(self.project_dir))
            self.assertTrue(harmless_dec.allowed, f"{ok_cmd}: {harmless_dec.reason}")

        # --- HIGH-2 & CRITICAL-1 runtime check: caller env cannot hijack PATH/PYTHONPATH or pop operator keys ---
        self.agy_env_file.write_text(
            "export AGY_ADC_AUTH=false\nexport CUSTOM_OP_FLAG=operator_locked\n",
            encoding="utf-8",
        )
        os.chmod(self.agy_env_file, 0o600)

        real_mns = can_use_mount_namespace()

        def _passthrough_ns(target_argv, **kwargs):
            import shlex as _shlex

            target_cwd = kwargs.get("cwd") or str(self.project_dir)
            return [
                "/bin/bash",
                "-c",
                f"cd {_shlex.quote(str(target_cwd))} && exec \"$@\"",
                "--",
                *target_argv,
            ]

        ns_patches = (
            []
            if real_mns
            else [
                patch("gateway.policy.can_use_mount_namespace", return_value=True),
                patch("gateway.executor.build_mount_ns_argv", side_effect=_passthrough_ns),
            ]
        )
        for p in ns_patches:
            p.start()
        try:
            adv_resp = await asyncio.to_thread(
                self.client._request_json,
                "POST",
                "/v1/agy",
                {
                    "prompt": evil_prompt,
                    "print_mode": False,
                    "cwd": str(self.project_dir),
                    "env": {
                        "PATH": "/tmp/evil_bin",
                        "PYTHONPATH": "/tmp/evil_py",
                        "NODE_OPTIONS": "--require=/tmp/evil.js",
                        "PYTHONDONTWRITEBYTECODE": "",
                        "AGY_PLUGIN_ROOT": "",
                        "CUSTOM_OP_FLAG": "",
                        "MOCK_PROBE_SECRET_PATH": str(self.tunnel_env_file),
                    },
                },
            )
            self.assertTrue(adv_resp["ok"], adv_resp)
            adv_out = json.loads(adv_resp["stdout"].strip())
            self.assertEqual(adv_out["positional_args"], [evil_prompt])
            self.assertFalse(adv_out["secret_read_allowed"])
            self.assertEqual(
                adv_out["secret_read_reason"], "Matches user-configured deny rule"
            )
            self.assertEqual(adv_out["dont_write_bytecode"], "1")
            self.assertEqual(adv_out["plugin_root_env"], str(self.plugin_dir))
            self.assertEqual(adv_out["custom_op_flag"], "operator_locked")
            self.assertIsNone(adv_out["pythonpath_env"])
            self.assertIsNone(adv_out["node_options_env"])
            self.assertNotEqual(adv_out["path_env"], "/tmp/evil_bin")

            # --- MEDIUM-3: Queued AGY session fails closed when plugins are disabled while queued ---
            self.server.sessions._agy_sem = asyncio.Semaphore(1)
            try:
                t1 = asyncio.create_task(
                    asyncio.to_thread(
                        self.client._request_json,
                        "POST",
                        "/v1/agy",
                        {
                            "prompt": "slot-holder",
                            "cwd": str(self.project_dir),
                            "env": {"MOCK_SLEEP_MS": "700"},
                        },
                    )
                )
                for _ in range(100):
                    if self.server.sessions.active_agy_count() >= 1:
                        break
                    await asyncio.sleep(0.01)
                t2 = asyncio.create_task(
                    asyncio.to_thread(
                        self.client._request_json,
                        "POST",
                        "/v1/agy",
                        {
                            "prompt": "queued-session",
                            "cwd": str(self.project_dir),
                        },
                    )
                )
                for _ in range(100):
                    if self.server.sessions.queued_agy_count() >= 1:
                        break
                    await asyncio.sleep(0.01)
                self.assertGreaterEqual(self.server.sessions.queued_agy_count(), 1)
                # Operator rolls back plugins while t2 is deterministically queued waiting on _agy_sem
                self._write_hot_plugins_registry(False, [str(self.plugin_dir)])
                r1, r2 = await asyncio.gather(t1, t2)
                self.assertTrue(r1["ok"], r1)
                self.assertFalse(r2["ok"], f"Queued session MUST fail closed: {r2}")
                self.assertEqual(r2["status"], "failed")
                self.assertIn("while session was queued", r2["stderr"])
            finally:
                self.server.sessions._agy_sem = asyncio.Semaphore(
                    self.cfg.max_concurrent_agy
                )
                self._write_hot_plugins_registry(True, [str(self.plugin_dir)])
        finally:
            for p in reversed(ns_patches):
                p.stop()

        # --- HIGH-3: Symlinked $HOME, symlinked ~/.gemini (home_covered), and symlinked ~/.gemini/config ---
        fake_home_real = self.runtime_base / "fake-home-real"
        fake_home_real.mkdir(parents=True, exist_ok=True)
        fake_home_link = self.runtime_base / "fake-home-link"
        os.symlink(fake_home_real, fake_home_link)

        with patch("gateway.policy.Path.home", return_value=fake_home_link):
            with self.assertRaises(PermissionError) as sym_home_err:
                pol.validate_agy_plugins(require_mount_ns_check=False)
            self.assertIn("HOME directory", str(sym_home_err.exception))

        # Symlinked ~/.gemini/config on host
        (fake_home_real / ".gemini").mkdir(parents=True, exist_ok=True)
        os.symlink("/tmp", fake_home_real / ".gemini" / "config")
        with patch("gateway.policy.Path.home", return_value=fake_home_real):
            with self.assertRaises(PermissionError) as sym_cfg_err:
                pol.validate_agy_plugins(require_mount_ns_check=False)
            self.assertIn("symlink", str(sym_cfg_err.exception).lower())
        with patch("gateway.sandbox.Path.home", return_value=fake_home_real), patch(
            "gateway.sandbox.can_use_mount_namespace", return_value=True
        ):
            with self.assertRaises(SandboxStorageError):
                build_mount_ns_argv(
                    [str(self.mock_agy_bin), "--sandbox"],
                    cwd=str(self.project_dir),
                    allowed_workdirs=self.cfg.allowed_workdirs,
                    protected_paths=self.cfg.protected_paths,
                    is_agy=True,
                    sandbox_state_dir=str(self.sandbox_dir),
                    agy_plugins_enabled=True,
                    agy_plugin_mounts=[("oh-my-agents", str(self.plugin_dir))],
                )
        (fake_home_real / ".gemini" / "config").unlink()

        # Symlinked ~/.gemini when home_covered=True
        shutil.rmtree(fake_home_real / ".gemini")
        os.symlink("/tmp", fake_home_real / ".gemini")
        home_cov_cfg = GatewayConfig(
            allowed_workdirs=[str(fake_home_real)],
            default_workdir=str(self.project_dir),
            protected_paths=[str(fake_home_real / ".gemini"), str(self.secrets_dir)],
            sandbox_state_dir=str(self.sandbox_dir),
            agy_binary=str(self.mock_agy_bin),
            agy_plugins_enabled=True,
            agy_plugin_dirs=[str(self.plugin_dir)],
            agy_plugins_file=str(self.secrets_dir / "none.json"),
        )
        with patch("gateway.policy.Path.home", return_value=fake_home_real):
            with self.assertRaises(PermissionError) as hc_sym_err:
                CommandPolicy(home_cov_cfg).validate_agy_plugins(
                    require_mount_ns_check=False
                )
            self.assertIn(".gemini", str(hc_sym_err.exception))
        (fake_home_real / ".gemini").unlink()

        # --- MEDIUM-1: FileService.list_dir hides workspace symlinks to plugin/secret, /opt ro & home_covered masking ---
        normal_file = self.project_dir / "visible_readme.md"
        normal_file.write_text("ok\n", encoding="utf-8")
        plugin_sym = self.project_dir / "sneaky_plugin_link"
        secret_sym = self.project_dir / "sneaky_secret_link"
        os.symlink(self.plugin_dir / "skills" / "spec-to-task" / "SKILL.md", plugin_sym)
        os.symlink(self.tunnel_env_file, secret_sym)
        try:
            ls_resp = await asyncio.to_thread(
                self.client.list_dir, str(self.project_dir)
            )
            listed_names = {e["name"] for e in ls_resp["entries"]}
            self.assertIn("visible_readme.md", listed_names)
            self.assertNotIn("sneaky_plugin_link", listed_names)
            self.assertNotIn("sneaky_secret_link", listed_names)
        finally:
            plugin_sym.unlink(missing_ok=True)
            secret_sym.unlink(missing_ok=True)

        # Verify /opt read-only remount + home_covered inactive plugin masking in VFS script
        fake_hc_plugin = _create_oh_my_agents_fixture(
            fake_home_real / "registered-plugins" / "oh-my-agents"
        )
        with patch("gateway.sandbox.Path.home", return_value=fake_home_real), patch(
            "gateway.sandbox.can_use_mount_namespace", return_value=True
        ):
            hc_argv = build_mount_ns_argv(
                ["/bin/true"],
                cwd=str(fake_home_real),
                allowed_workdirs=[str(fake_home_real)],
                protected_paths=[str(fake_home_real / ".gemini")],
                is_agy=False,
                sandbox_state_dir=str(self.sandbox_dir),
                agy_plugins_enabled=False,
                masked_plugin_paths=[str(fake_hc_plugin)],
            )
        hc_script = hc_argv[hc_argv.index("-c") + 1]
        self.assertNotIn('--bind /opt "/media/opt"', hc_script)
        self.assertIn('remount,bind,ro "/media/opt"', hc_script)
        self.assertIn("/media/opt/*)", hc_script)
        self.assertIn(str(fake_hc_plugin), hc_script)
        self.assertIn("mode=0555,ro tmpfs", hc_script)

        # --- MEDIUM-2: Stale settings.json plugin allow cleanup after clear & corrupt settings.json fail-closed ---
        stale_settings_path = (
            fake_home_real / ".gemini" / "antigravity-cli" / "settings.json"
        )
        stale_settings_path.parent.mkdir(parents=True, exist_ok=True)
        stale_settings_path.write_text(
            json.dumps(
                {
                    "permissions": {
                        "allow": [
                            "read_file(~/.gemini/config/plugins/oh-my-agents)",
                            f"read_file({fake_home_real / '.gemini' / 'config' / 'plugins' / 'legacy'})",
                            "read_file(/usr/share)",
                        ],
                        "deny": [],
                    }
                }
            ),
            encoding="utf-8",
        )
        cleared_cfg = GatewayConfig(
            allowed_workdirs=[str(self.workspace_root)],
            default_workdir=str(self.workspace_root),
            sandbox_state_dir=str(self.sandbox_dir),
            agy_plugins_enabled=False,
            agy_plugin_dirs=[],
            agy_plugins_file=str(self.secrets_dir / "cleared-none.json"),
        )
        with patch("gateway.policy.Path.home", return_value=fake_home_real), patch.dict(
            os.environ, {"HOME": str(fake_home_real)}
        ):
            cleaned = CommandPolicy(cleared_cfg).build_agy_sandbox_settings(
                cwd=str(self.project_dir)
            )
        self.assertIn("read_file(/usr/share)", cleaned["permissions"]["allow"])
        self.assertFalse(
            any(
                ".gemini/config/plugins" in r
                for r in cleaned["permissions"]["allow"]
            ),
            cleaned["permissions"]["allow"],
        )

        # Corrupt ~/.gemini/antigravity-cli/settings.json MUST fail closed
        stale_settings_path.write_text("{corrupt-settings-json", encoding="utf-8")
        with patch("gateway.policy.Path.home", return_value=fake_home_real):
            with self.assertRaises(PermissionError) as bad_set_err:
                CommandPolicy(cleared_cfg).build_agy_sandbox_settings(
                    cwd=str(self.project_dir)
                )
            self.assertIn("settings.json", str(bad_set_err.exception))


if __name__ == "__main__":
    unittest.main()
