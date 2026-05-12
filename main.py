from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register


@dataclass(frozen=True)
class SshRunResult:
    exit_status: int
    stdout: str
    stderr: str


@register(
    "astrbot_plugin_iris_sshtoolspack",
    "NOTFROMCONCEN",
    "在 IM 入口透传 SSH 命令到指定服务器执行",
    "1.0.1-beta",
)
class IrisSshToolsPackPlugin(Star):
    def __init__(self, context: Context, config: dict[str, Any] | None = None):
        super().__init__(context)
        self.config = config or {}
        self._admin_ids_cache: set[str] = set()
        self._admin_ids_sig = ""
        self._commands_total = 0
        self._commands_ok = 0
        self._commands_fail = 0
        self._last_error = ""
        self._max_log_line_length = self._int_conf("max_log_line_length", 512)
        self._log_verbose(
            f"startup: enabled={self._is_enabled()} profile={self._profile_name()} "
            f"host={self._ssh_host()} port={self._ssh_port()}"
        )

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

    async def _handle_ssh_exec(self, event: AstrMessageEvent):
        if not self._is_enabled():
            yield event.plain_result("Iris SSH 工具包未启用")
            return

        if not self._is_manager(event):
            yield event.plain_result("无权限执行 SSH 命令")
            return

        profile, command = self._parse_exec_args(event.message_str or "")
        if not command:
            yield event.plain_result(self._help_text())
            return

        conf_error = self._validate_ssh_config(profile)
        if conf_error:
            yield event.plain_result(conf_error)
            return

        self._commands_total += 1
        self._log_verbose(f"exec: profile={profile} command={self._preview(command)}")

        try:
            result = await asyncio.to_thread(self._run_ssh_command, command)
        except Exception as e:
            self._commands_fail += 1
            self._last_error = self._norm(e)
            logger.warning(f"[iris_sshtoolspack] SSH 执行失败: {e}")
            yield event.plain_result(f"SSH 执行失败: {e}")
            return

        if result.exit_status == 0:
            self._commands_ok += 1
        else:
            self._commands_fail += 1

        yield event.plain_result(self._format_exec_result(profile, command, result))

    async def _handle_status(self, event: AstrMessageEvent):
        if not self._is_manager(event):
            yield event.plain_result("无权限查看 SSH 状态")
            return

        auth_mode = "private_key" if self._private_key_path() else "password"
        host = self._ssh_host() or "未配置"
        lines = [
            "[Iris SSH 工具包]",
            f"- enabled: {self._is_enabled()}",
            f"- profile: {self._profile_name()}",
            f"- target: {self._ssh_username() or '未配置'}@{host}:{self._ssh_port()}",
            f"- auth_mode: {auth_mode}",
            f"- commands_total/ok/fail: {self._commands_total}/{self._commands_ok}/{self._commands_fail}",
            f"- command_timeout_sec: {self._command_timeout()}",
            f"- last_error: {self._last_error or 'none'}",
        ]
        yield event.plain_result("\n".join(lines))

    def _run_ssh_command(self, command: str) -> SshRunResult:
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
            "hostname": self._ssh_host(),
            "port": self._ssh_port(),
            "username": self._ssh_username(),
            "timeout": self._connect_timeout(),
            "banner_timeout": self._connect_timeout(),
            "auth_timeout": self._connect_timeout(),
            "look_for_keys": False,
            "allow_agent": False,
        }
        private_key_path = self._private_key_path()
        if private_key_path:
            kwargs["key_filename"] = private_key_path
            passphrase = self._private_key_passphrase()
            if passphrase:
                kwargs["passphrase"] = passphrase
        else:
            kwargs["password"] = self._ssh_password()

        try:
            client.connect(**kwargs)
            stdin, stdout, stderr = client.exec_command(
                command, timeout=self._command_timeout()
            )
            stdin.close()
            exit_status = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return SshRunResult(exit_status=exit_status, stdout=out, stderr=err)
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

    def _format_exec_result(
        self, profile: str, command: str, result: SshRunResult
    ) -> str:
        body_parts = []
        if result.stdout.strip():
            body_parts.append(result.stdout.rstrip())
        if result.stderr.strip():
            body_parts.append("[stderr]\n" + result.stderr.rstrip())
        body = "\n".join(body_parts).strip() or "(no output)"
        body = self._truncate(body, self._max_output_chars())
        return (
            f"[SSH:{profile}] exit={result.exit_status}\n"
            f"$ {command}\n\n"
            f"{body}"
        )

    def _validate_ssh_config(self, profile: str) -> str:
        if profile != self._profile_name():
            return f"未知 SSH 配置: {profile}"
        if not self._ssh_host():
            return "未配置 ssh_host"
        if not self._ssh_username():
            return "未配置 ssh_username"
        if not self._private_key_path() and not self._ssh_password():
            return "未配置 ssh_password 或 ssh_private_key_path"
        key_path = self._private_key_path()
        if key_path and not Path(key_path).expanduser().exists():
            return f"SSH 私钥不存在: {key_path}"
        return ""

    def _help_text(self) -> str:
        profile = self._profile_name()
        return (
            "[Iris SSH 工具包]\n"
            "用法:\n"
            f"- /ssh_exec <command>\n"
            f"- /ssh_exec {profile} <command>\n"
            "- /SSH执行 <命令>\n"
            "- /SSH執行 <命令>\n"
            "示例:\n"
            "- /ssh_exec uptime\n"
            "- /SSH执行 df -h"
        )

    def _is_enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    def _profile_name(self) -> str:
        return self._norm(self.config.get("ssh_profile_name", "default")) or "default"

    def _ssh_host(self) -> str:
        return self._norm(self.config.get("ssh_host", ""))

    def _ssh_port(self) -> int:
        return max(1, min(65535, self._int_conf("ssh_port", 22)))

    def _ssh_username(self) -> str:
        return self._norm(self.config.get("ssh_username", ""))

    def _ssh_password(self) -> str:
        return self._norm(self.config.get("ssh_password", ""))

    def _private_key_path(self) -> str:
        return self._norm(self.config.get("ssh_private_key_path", ""))

    def _private_key_passphrase(self) -> str:
        return self._norm(self.config.get("ssh_private_key_passphrase", ""))

    def _connect_timeout(self) -> int:
        return max(1, self._int_conf("connect_timeout_sec", 10))

    def _command_timeout(self) -> int:
        return max(1, self._int_conf("command_timeout_sec", 30))

    def _max_output_chars(self) -> int:
        return max(200, self._int_conf("max_output_chars", 3500))

    def _allow_unknown_host(self) -> bool:
        return bool(self.config.get("allow_unknown_host", True))

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

    async def terminate(self):
        logger.info("[iris_sshtoolspack] terminated")
