from __future__ import annotations

import asyncio
import hashlib
import json
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

_UTILS_PATH = Path(__file__).resolve().parent.parent / "utils"
if str(_UTILS_PATH) not in sys.path:
    sys.path.insert(0, str(_UTILS_PATH))

try:
    from command_parser import parse_command
    from config_utils import env_override, mask_key
except Exception:
    parse_command = None  # type: ignore[misc]
    env_override = None  # type: ignore[misc]
    mask_key = None  # type: ignore[misc]

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register

from audit_store import AuditStore

try:
    from config_utils import scan_sensitive_data
except Exception:
    scan_sensitive_data = None  # type: ignore[misc]


@dataclass(frozen=True)
class SshRunResult:
    exit_status: int
    stdout: str
    stderr: str
    duration_ms: int = 0


@dataclass
class AuditRecord:
    timestamp: str
    sender_id: str
    profile: str
    host: str
    command_preview: str
    exit_status: int
    duration_ms: int
    allowed: bool
    block_reason: str = ""


@register(
    "astrbot_plugin_iris_sshtoolspack",
    "NOTFROMCONCEN",
    "在 IM 入口透传 SSH 命令到指定服务器执行",
    "2.2.2",
)
class IrisSshToolsPackPlugin(Star):
    def __init__(self, context: Context, config: dict[str, Any] | None = None):
        super().__init__(context)
        self.config = config or {}
        self._load_secure_config()

        self._admin_ids_cache: set[str] = set()
        self._admin_ids_sig = ""
        self._commands_total = 0
        self._commands_ok = 0
        self._commands_fail = 0
        self._commands_blocked = 0
        self._last_error = ""
        self._max_log_line_length = self._int_conf("max_log_line_length", 512)
        self._allow_patterns_sig = ""
        self._deny_patterns_sig = ""
        self._allow_patterns_compiled: list[re.Pattern[str]] = []
        self._deny_patterns_compiled: list[re.Pattern[str]] = []

        audit_mode = self._norm(self.config.get("audit_mode", "memory"))
        audit_dir_raw = self._norm(self.config.get("audit_dir", ""))
        audit_dir = Path(audit_dir_raw) if audit_dir_raw else Path(__file__).resolve().parent / "data"
        self._audit_store = AuditStore(audit_mode, audit_dir, max_memory=self._int_conf("audit_max_records", 200))

        self._pending_confirmations: dict[str, dict[str, Any]] = {}
        self._interactive_confirm = bool(self.config.get("interactive_confirm", False))
        self._confirm_timeout_sec = max(10, self._int_conf("interactive_confirm_timeout_sec", 60))
        self._key_rotate_warn_days = max(0, self._int_conf("key_rotate_warn_days", 90))

        self._scan_sensitive_config()

        self._log_verbose(
            f"startup: enabled={self._is_enabled()} profiles={list(self._profiles().keys())}"
        )

    def _load_secure_config(self) -> None:
        """ENV 覆盖敏感字段。"""
        if env_override is None:
            return
        # 对默认 profile 的敏感字段做 ENV 覆盖
        default = self._profile_name()
        profiles = self._profiles()
        if default in profiles:
            p = profiles[default]
            p["ssh_password"] = env_override(
                p, "ssh_password", "IRIS_SSH_PASSWORD"
            ) or p.get("ssh_password", "")
            p["ssh_private_key_passphrase"] = env_override(
                p, "ssh_private_key_passphrase", "IRIS_SSH_KEY_PASSPHRASE"
            ) or p.get("ssh_private_key_passphrase", "")

    @filter.command("ssh_exec")
    async def ssh_exec_en(self, event: AstrMessageEvent):
        async for result in self._handle_ssh_exec(event):
            yield result

    @filter.command("SSH执行")
    async def ssh_exec_cn(self, event: AstrMessageEvent):
        async for result in self._handle_ssh_exec(event):
            yield result

    @filter.command("SSH執行")
    async def ssh_exec_tw(self, event: AstrMessageEvent):
        async for result in self._handle_ssh_exec(event):
            yield result

    @filter.command("ssh_status")
    async def ssh_status_en(self, event: AstrMessageEvent):
        async for result in self._handle_status(event):
            yield result

    @filter.command("SSH状态")
    async def ssh_status_cn(self, event: AstrMessageEvent):
        async for result in self._handle_status(event):
            yield result

    @filter.command("SSH狀態")
    async def ssh_status_tw(self, event: AstrMessageEvent):
        async for result in self._handle_status(event):
            yield result

    @filter.command("ssh_help")
    async def ssh_help_en(self, event: AstrMessageEvent):
        yield event.plain_result(self._help_text())

    @filter.command("SSH帮助")
    async def ssh_help_cn(self, event: AstrMessageEvent):
        yield event.plain_result(self._help_text())

    @filter.command("SSH幫助")
    async def ssh_help_tw(self, event: AstrMessageEvent):
        yield event.plain_result(self._help_text())

    @filter.command("ssh_audit")
    async def ssh_audit_en(self, event: AstrMessageEvent):
        async for result in self._handle_audit(event):
            yield result

    @filter.command("SSH审计")
    async def ssh_audit_cn(self, event: AstrMessageEvent):
        async for result in self._handle_audit(event):
            yield result

    async def _handle_ssh_exec(self, event: AstrMessageEvent):
        if not self._is_enabled():
            yield event.plain_result("Iris SSH 工具包未启用")
            return

        if not self._is_manager(event):
            yield event.plain_result("无权限执行 SSH 命令")
            return

        raw = event.message_str or ""
        if parse_command is not None:
            parsed = parse_command(raw)
            profile, command = self._parse_exec_args_parsed(parsed)
        else:
            profile, command = self._parse_exec_args(raw)

        if not command:
            yield event.plain_result(self._help_text())
            return

        conf_error = self._validate_ssh_config(profile)
        if conf_error:
            yield event.plain_result(conf_error)
            return

        # 命令白名单/黑名单检查
        allowed, reason = self._check_command_policy(command)
        sender_id = self._norm(event.get_sender_id())

        if not allowed:
            self._commands_total += 1
            self._commands_blocked += 1
            self._audit_store.append(
                AuditRecord(
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    sender_id=sender_id,
                    profile=profile,
                    host=self._ssh_host(profile),
                    command_preview=self._preview(command),
                    exit_status=-1,
                    duration_ms=0,
                    allowed=False,
                    block_reason=reason,
                )
            )
            self._log_verbose(f"blocked command: profile={profile} reason={reason} preview={self._preview(command)}")
            yield event.plain_result(f"命令被策略拦截: {reason}\n$ {command}")
            return

        # 危险命令二次确认
        if self._interactive_confirm and self._is_dangerous_command(command):
            confirm_id = self._generate_confirm_id()
            self._pending_confirmations[confirm_id] = {
                "profile": profile,
                "command": command,
                "sender_id": sender_id,
                "ts": time.time(),
            }
            self._log_verbose(f"confirm requested: id={confirm_id} profile={profile} preview={self._preview(command)}")
            yield event.plain_result(
                f"检测到危险命令，需要二次确认:\n$ {command}\n"
                f"管理员请回复: /ssh_confirm {confirm_id}\n"
                f"超时时间: {self._confirm_timeout_sec} 秒"
            )
            return

        self._commands_total += 1
        self._log_verbose(f"exec: profile={profile} command={self._preview(command)}")

        t0 = time.time()
        try:
            result = await asyncio.to_thread(self._run_ssh_command, profile, command)
        except Exception as e:
            self._commands_fail += 1
            self._last_error = self._norm(e)
            logger.warning(f"[iris_sshtoolspack] SSH 执行失败: {e}")
            self._audit_store.append(
                AuditRecord(
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    sender_id=sender_id,
                    profile=profile,
                    host=self._ssh_host(profile),
                    command_preview=self._preview(command),
                    exit_status=-1,
                    duration_ms=int((time.time() - t0) * 1000),
                    allowed=True,
                    block_reason=str(e),
                )
            )
            yield event.plain_result(f"SSH 执行失败: {e}")
            return

        if result.exit_status == 0:
            self._commands_ok += 1
        else:
            self._commands_fail += 1

        self._audit_store.append(
            AuditRecord(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                sender_id=sender_id,
                profile=profile,
                host=self._ssh_host(profile),
                command_preview=self._preview(command),
                exit_status=result.exit_status,
                duration_ms=result.duration_ms,
                allowed=True,
            )
        )

        for part in self._format_exec_result_parts(profile, command, result):
            yield event.plain_result(part)

    async def _handle_status(self, event: AstrMessageEvent):
        if not self._is_manager(event):
            yield event.plain_result("无权限查看 SSH 状态")
            return

        profile = self._profile_name()
        auth_mode = "private_key" if self._private_key_path(profile) else "password"
        host = self._ssh_host(profile) or "未配置"
        lines = [
            "[Iris SSH 工具包]",
            f"- enabled: {self._is_enabled()}",
            f"- active_profile: {profile}",
            f"- profiles: {', '.join(self._profiles().keys()) or 'default'}",
            f"- target: {self._ssh_username(profile) or '未配置'}@{host}:{self._ssh_port(profile)}",
            f"- auth_mode: {auth_mode}",
            f"- allow_unknown_host: {self._allow_unknown_host()}",
            f"- commands_total/ok/fail/blocked: {self._commands_total}/{self._commands_ok}/{self._commands_fail}/{self._commands_blocked}",
            f"- command_timeout_sec: {self._command_timeout()}",
            f"- last_error: {self._last_error or 'none'}",
            f"- command_policy: {self._command_policy_desc()}",
            f"- audit_mode: {self._audit_store.mode}",
            f"- interactive_confirm: {self._interactive_confirm}",
        ]

        # 密钥轮换提示
        key_path = self._private_key_path(profile)
        if key_path and self._key_rotate_warn_days > 0:
            rotate_hint = self._key_rotate_hint(key_path)
            if rotate_hint:
                lines.append(f"- key_rotate_hint: {rotate_hint}")

        yield event.plain_result("\n".join(lines))

    async def _handle_audit(self, event: AstrMessageEvent):
        if not self._is_manager(event):
            yield event.plain_result("无权限查看审计日志")
            return
        records = self._audit_store.query(limit=20)
        if not records:
            yield event.plain_result("暂无审计记录")
            return
        lines = ["[SSH 审计记录]"]
        for r in records:
            status = "放行" if r.get("allowed") else "拦截"
            lines.append(
                f"[{r.get('timestamp')}] {status} | {r.get('sender_id')} | {r.get('profile')}@{r.get('host')} | exit={r.get('exit_status')} | {r.get('duration_ms')}ms | {r.get('command_preview')}"
            )
            if r.get("block_reason"):
                lines.append(f"  -> reason: {r.get('block_reason')}")
        yield event.plain_result("\n".join(lines))

    def _run_ssh_command(self, profile: str, command: str) -> SshRunResult:
        try:
            import paramiko
        except ImportError as e:
            raise RuntimeError("缺少依赖 paramiko，请先安装 requirements.txt") from e

        client = paramiko.SSHClient()
        if self._allow_unknown_host():
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        kwargs: dict[str, Any] = {
            "hostname": self._ssh_host(profile),
            "port": self._ssh_port(profile),
            "username": self._ssh_username(profile),
            "timeout": self._connect_timeout(),
            "banner_timeout": self._connect_timeout(),
            "auth_timeout": self._connect_timeout(),
            "look_for_keys": False,
            "allow_agent": False,
        }
        private_key_path = self._private_key_path(profile)
        if private_key_path:
            kwargs["key_filename"] = private_key_path
            passphrase = self._private_key_passphrase(profile)
            if passphrase:
                kwargs["passphrase"] = passphrase
        else:
            kwargs["password"] = self._ssh_password(profile)

        t0 = time.time()
        try:
            client.connect(**kwargs)
            stdin, stdout, stderr = client.exec_command(
                command, timeout=self._command_timeout()
            )
            stdin.close()
            exit_status = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            duration_ms = int((time.time() - t0) * 1000)
            return SshRunResult(exit_status=exit_status, stdout=out, stderr=err, duration_ms=duration_ms)
        except socket.timeout as e:
            raise RuntimeError(f"SSH 命令超时（{self._command_timeout()} 秒）") from e
        finally:
            client.close()

    def _parse_exec_args(self, raw: str) -> tuple[str, str]:
        text = (raw or "").strip()
        if not text:
            return self._profile_name(), ""

        parts = text.split(maxsplit=2)
        if len(parts) <= 1:
            return self._profile_name(), ""

        profile = self._profile_name()
        if len(parts) >= 3 and parts[1] == profile:
            return profile, parts[2].strip()

        return profile, text[len(parts[0]) :].strip()

    def _parse_exec_args_parsed(self, parsed: Any) -> tuple[str, str]:
        if not parsed.args:
            return self._profile_name(), ""
        profile = self._profile_name()
        if parsed.args[0] in self._profiles():
            profile = parsed.args[0]
            command = parsed.join_after(1)
        else:
            command = parsed.join_after(0)
        return profile, command

    def _format_exec_result_parts(
        self, profile: str, command: str, result: SshRunResult
    ) -> list[str]:
        body_parts = []
        if result.stdout.strip():
            body_parts.append(result.stdout.rstrip())
        if result.stderr.strip():
            body_parts.append("[stderr]\n" + result.stderr.rstrip())
        body = "\n".join(body_parts).strip() or "(no output)"
        header = f"[SSH:{profile}] exit={result.exit_status} time={result.duration_ms}ms\n$ {command}\n"
        max_chars = self._max_output_chars()
        if len(body) <= max_chars:
            return [header + body]
        # 分片输出
        chunks = self._chunk_text(body, max_chars)
        parts: list[str] = []
        total = len(chunks)
        for idx, chunk in enumerate(chunks, 1):
            parts.append(f"{header}[{idx}/{total}]\n{chunk}")
            header = ""  # 只有第一条带 header
        return parts

    @staticmethod
    def _chunk_text(text: str, max_chars: int) -> list[str]:
        if len(text) <= max_chars:
            return [text]
        lines = text.splitlines()
        chunks: list[str] = []
        current = ""
        for line in lines:
            if len(current) + len(line) + 1 > max_chars:
                if current:
                    chunks.append(current.rstrip())
                current = line
            else:
                current = (current + "\n" + line).strip() if current else line
        if current:
            chunks.append(current.rstrip())
        return chunks or [text[:max_chars]]

    def _validate_ssh_config(self, profile: str) -> str:
        if profile not in self._profiles():
            return f"未知 SSH 配置: {profile}"
        if not self._ssh_host(profile):
            return "未配置 ssh_host"
        if not self._ssh_username(profile):
            return "未配置 ssh_username"
        if not self._private_key_path(profile) and not self._ssh_password(profile):
            return "未配置 ssh_password 或 ssh_private_key_path"
        key_path = self._private_key_path(profile)
        if key_path and not Path(key_path).expanduser().exists():
            return f"SSH 私钥不存在: {key_path}"
        return ""

    def _help_text(self) -> str:
        profile = self._profile_name()
        profiles = ", ".join(self._profiles().keys()) or "default"
        return (
            "[Iris SSH 工具包]\n"
            "用法:\n"
            f"- /ssh_exec <command>\n"
            f"- /ssh_exec <profile> <command>\n"
            "- /SSH执行 <命令>\n"
            "- /SSH執行 <命令>\n"
            f"可用 profiles: {profiles}\n"
            "示例:\n"
            "- /ssh_exec uptime\n"
            f"- /ssh_exec {profile} df -h"
        )

    def _check_command_policy(self, command: str) -> tuple[bool, str]:
        """返回 (allowed, reason)。"""
        allow_patterns = self._command_allow_patterns()
        deny_patterns = self._command_deny_patterns()
        allow_compiled, deny_compiled = self._compiled_policy_patterns(allow_patterns, deny_patterns)
        preview = command.strip()

        # 黑名单优先
        for idx, regex in enumerate(deny_compiled):
            if regex.search(preview):
                pat = deny_patterns[idx] if idx < len(deny_patterns) else regex.pattern
                return False, f"命中黑名单正则: {pat}"

        if not allow_patterns:
            # 未配置白名单则全部放行（除黑名单外）
            return True, ""

        for regex in allow_compiled:
            if regex.search(preview):
                return True, ""
        return False, "未命中命令白名单"

    def _compiled_policy_patterns(
        self, allow_patterns: list[str], deny_patterns: list[str]
    ) -> tuple[list[re.Pattern[str]], list[re.Pattern[str]]]:
        allow_sig = "|".join(allow_patterns)
        deny_sig = "|".join(deny_patterns)
        if allow_sig != self._allow_patterns_sig:
            self._allow_patterns_sig = allow_sig
            self._allow_patterns_compiled = self._compile_patterns(allow_patterns, "allow")
        if deny_sig != self._deny_patterns_sig:
            self._deny_patterns_sig = deny_sig
            self._deny_patterns_compiled = self._compile_patterns(deny_patterns, "deny")
        return self._allow_patterns_compiled, self._deny_patterns_compiled

    def _compile_patterns(self, patterns: list[str], mode: str) -> list[re.Pattern[str]]:
        compiled: list[re.Pattern[str]] = []
        for pat in patterns:
            try:
                compiled.append(re.compile(pat))
            except re.error as e:
                logger.warning(f"[iris_sshtoolspack] ignore invalid {mode} regex '{pat}': {e}")
        return compiled

    def _command_allow_patterns(self) -> list[str]:
        raw = self.config.get("command_allow_patterns", [])
        if isinstance(raw, list):
            return [str(p).strip() for p in raw if str(p).strip()]
        if isinstance(raw, str) and raw.strip():
            return [raw.strip()]
        return []

    def _command_deny_patterns(self) -> list[str]:
        defaults = [
            r"^\s*rm\s+-rf\s+/\s*",
            r"^\s*mkfs\.",
            r"^\s*dd\s+if=.+of=/dev/",
            r">\s*/dev/\w+\s*;?\s*$",
        ]
        raw = self.config.get("command_deny_patterns", [])
        customs: list[str] = []
        if isinstance(raw, list):
            customs = [str(p).strip() for p in raw if str(p).strip()]
        elif isinstance(raw, str) and raw.strip():
            customs = [raw.strip()]
        return defaults + customs

    def _command_policy_desc(self) -> str:
        allow = self._command_allow_patterns()
        deny = self._command_deny_patterns()
        if allow:
            return f"白名单({len(allow)}条) + 黑名单({len(deny)}条)"
        return f"仅黑名单({len(deny)}条)，无白名单限制"


    def _profiles(self) -> dict[str, dict[str, Any]]:
        """返回所有 profile 配置，始终包含 default。"""
        profiles = self.config.get("ssh_profiles")
        if isinstance(profiles, dict) and profiles:
            # 确保 default 存在
            default_name = self._norm(self.config.get("ssh_profile_name", "default"))
            base = self._base_profile()
            result: dict[str, dict[str, Any]] = {}
            for name, p in profiles.items():
                merged = {**base, **p}
                result[self._norm(name)] = merged
            if default_name not in result:
                result[default_name] = base
            return result
        return {self._profile_name(): self._base_profile()}

    def _base_profile(self) -> dict[str, Any]:
        return {
            "ssh_host": self.config.get("ssh_host", ""),
            "ssh_port": self.config.get("ssh_port", 22),
            "ssh_username": self.config.get("ssh_username", ""),
            "ssh_password": self.config.get("ssh_password", ""),
            "ssh_private_key_path": self.config.get("ssh_private_key_path", ""),
            "ssh_private_key_passphrase": self.config.get("ssh_private_key_passphrase", ""),
        }

    def _is_enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    def _profile_name(self) -> str:
        return self._norm(self.config.get("ssh_profile_name", "default")) or "default"

    def _ssh_host(self, profile: str = "") -> str:
        return self._profile_val(profile, "ssh_host", "")

    def _ssh_port(self, profile: str = "") -> int:
        return max(1, min(65535, self._int_conf("ssh_port", 22)))

    def _ssh_username(self, profile: str = "") -> str:
        return self._profile_val(profile, "ssh_username", "")

    def _ssh_password(self, profile: str = "") -> str:
        return self._profile_val(profile, "ssh_password", "")

    def _private_key_path(self, profile: str = "") -> str:
        return self._profile_val(profile, "ssh_private_key_path", "")

    def _private_key_passphrase(self, profile: str = "") -> str:
        return self._profile_val(profile, "ssh_private_key_passphrase", "")

    def _profile_val(self, profile: str, key: str, default: Any) -> Any:
        profiles = self._profiles()
        p = profiles.get(profile) or profiles.get(self._profile_name()) or {}
        return p.get(key, default)

    def _connect_timeout(self) -> int:
        return max(1, self._int_conf("connect_timeout_sec", 10))

    def _command_timeout(self) -> int:
        return max(1, self._int_conf("command_timeout_sec", 30))

    def _max_output_chars(self) -> int:
        return max(200, self._int_conf("max_output_chars", 3500))

    def _allow_unknown_host(self) -> bool:
        # 安全加固：默认关闭
        return bool(self.config.get("allow_unknown_host", False))

    def _is_manager(self, event: AstrMessageEvent) -> bool:
        sender_id = self._norm(event.get_sender_id())
        if sender_id in self._manager_ids():
            return True

        if bool(self.config.get("allow_astrbot_admin", True)):
            try:
                return bool(event.is_admin())
            except Exception:
                return False

        return False

    def _manager_ids(self) -> set[str]:
        raw = self.config.get("admin_user_ids", []) or []
        normalized = [self._norm(i) for i in raw if self._norm(i)]
        sig = "|".join(sorted(normalized))
        if sig != self._admin_ids_sig:
            self._admin_ids_sig = sig
            self._admin_ids_cache = set(normalized)
        return self._admin_ids_cache

    def _int_conf(self, key: str, default: int) -> int:
        try:
            return int(self.config.get(key, default))
        except Exception:
            return default

    def _log_verbose(self, text: str):
        if not bool(self.config.get("verbose_log", False)):
            return
        msg = f"[iris_sshtoolspack] {text}"
        if len(msg) > self._max_log_line_length:
            msg = msg[: self._max_log_line_length] + "...[truncated]"
        logger.info(msg)

    def _preview(self, text: str) -> str:
        return self._truncate(text.replace("\n", " "), 120)

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n...[truncated]"

    @staticmethod
    def _norm(v: Any) -> str:
        if v is None:
            return ""
        return str(v).strip()

    def _scan_sensitive_config(self) -> None:
        if scan_sensitive_data is None:
            return
        try:
            found = scan_sensitive_data(self.config, "config")
            if found:
                for path in found:
                    logger.warning(
                        f"[iris_sshtoolspack] 配置中发现明文敏感字段: {path}，"
                        "建议使用环境变量覆盖（ENV）"
                    )
        except Exception as e:
            self._log_verbose(f"scan_sensitive_config error: {e}")

    @staticmethod
    def _key_rotate_hint(key_path: str) -> str:
        try:
            import os
            stat = os.stat(Path(key_path).expanduser())
            age_days = int((time.time() - stat.st_mtime) / 86400)
            return f"私钥已使用 {age_days} 天，建议轮换" if age_days > 90 else ""
        except Exception:
            return ""

    @staticmethod
    def _is_dangerous_command(command: str) -> bool:
        patterns = [
            r"^\s*rm\s+-rf\s+/",
            r"^\s*mkfs\.",
            r"^\s*dd\s+if=.+of=/dev/",
            r">\s*/dev/\w+\s*;?\s*$",
            r"^\s*reboot\b",
            r"^\s*halt\b",
            r"^\s*poweroff\b",
            r"^\s*shutdown\b",
            r"^\s*init\s+0",
            r"^\s*init\s+6",
        ]
        for pat in patterns:
            if re.search(pat, command.strip()):
                return True
        return False

    def _generate_confirm_id(self) -> str:
        import secrets
        return secrets.token_urlsafe(8)

    @filter.command("ssh_confirm")
    async def ssh_confirm(self, event: AstrMessageEvent):
        sender_id = self._norm(event.get_sender_id())
        if not self._is_manager(event):
            yield event.plain_result("无权限执行确认")
            return
        raw = event.message_str or ""
        tokens = raw.strip().split()
        if len(tokens) < 2:
            yield event.plain_result("用法: /ssh_confirm <确认ID>")
            return
        confirm_id = tokens[1]
        info = self._pending_confirmations.pop(confirm_id, None)
        if not info:
            yield event.plain_result("确认 ID 不存在或已过期")
            return
        profile = info["profile"]
        command = info["command"]
        self._log_verbose(f"confirmed: id={confirm_id} profile={profile} command={self._preview(command)}")
        t0 = time.time()
        try:
            result = await asyncio.to_thread(self._run_ssh_command, profile, command)
        except Exception as e:
            self._commands_fail += 1
            self._last_error = self._norm(e)
            logger.warning(f"[iris_sshtoolspack] SSH 执行失败: {e}")
            self._audit_store.append(
                AuditRecord(
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    sender_id=sender_id,
                    profile=profile,
                    host=self._ssh_host(profile),
                    command_preview=self._preview(command),
                    exit_status=-1,
                    duration_ms=int((time.time() - t0) * 1000),
                    allowed=True,
                    block_reason=str(e),
                )
            )
            yield event.plain_result(f"SSH 执行失败: {e}")
            return
        if result.exit_status == 0:
            self._commands_ok += 1
        else:
            self._commands_fail += 1
        self._audit_store.append(
            AuditRecord(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                sender_id=sender_id,
                profile=profile,
                host=self._ssh_host(profile),
                command_preview=self._preview(command),
                exit_status=result.exit_status,
                duration_ms=result.duration_ms,
                allowed=True,
            )
        )
        for part in self._format_exec_result_parts(profile, command, result):
            yield event.plain_result(part)

    async def terminate(self):
        logger.info("[iris_sshtoolspack] terminated")


