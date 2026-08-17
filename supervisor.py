#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import threading
import time
from typing import Any


DEFAULT_PROXY_PORT = 8888
DEFAULT_ADMIN_PORT = 8889
DEFAULT_HEALTHCHECK_URL = "https://www.youtube.com/generate_204"
DEFAULT_TUNNEL_HEALTHCHECK_URL = "https://www.gstatic.com/generate_204"
DEFAULT_HEALTHCHECK_CONNECT_TIMEOUT = 12
DEFAULT_HEALTHCHECK_MAX_TIME = 30
DEFAULT_PROXY_DRAIN_TIMEOUT = 10
MAX_REQUEST_BYTES = 16 * 1024


class RotationBusy(RuntimeError):
    pass


class HealthcheckError(RuntimeError):
    pass


class CommandError(RuntimeError):
    def __init__(self, command: list[str], output: str):
        self.command = command
        self.output = output.strip()
        command_text = " ".join(command)
        message = f"{command_text} failed"
        if self.output:
            message = f"{message}: {self.output}"
        super().__init__(message)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: str


def log(message: str) -> None:
    print(f"[proxy-manager] {message}", flush=True)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace(
        "+00:00",
        "Z",
    )


def parse_int(value: str, *, name: str, minimum: int = 0) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {value!r}") from exc
    if parsed < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}, got {parsed}")
    return parsed


def env_int(name: str, default: int, *, minimum: int = 0) -> int:
    return parse_int(os.environ.get(name, str(default)), name=name, minimum=minimum)


def run_command(
    command: list[str],
    *,
    check: bool = True,
    timeout: int | None = None,
) -> CommandResult:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    output = completed.stdout or ""
    if check and completed.returncode != 0:
        raise CommandError(command, output)
    return CommandResult(completed.returncode, output)


def count_ss_connections(output: str) -> int:
    return sum(1 for line in output.splitlines() if line.strip())


def proxy_reject_rule(proxy_port: int) -> list[str]:
    # Match only NEW connections so requests already in flight keep their
    # packets accepted and can drain, instead of being reset mid-request.
    return [
        "INPUT",
        "!",
        "-i",
        "lo",
        "-p",
        "tcp",
        "--dport",
        str(proxy_port),
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-j",
        "REJECT",
        "--reject-with",
        "tcp-reset",
    ]


def assigned_config_paths(
    all_configs: list[Path],
    *,
    slot_count: int,
    slot_index: int,
    config_limit: int | None,
) -> list[Path]:
    assigned_configs = [
        path
        for index, path in enumerate(all_configs)
        if index % slot_count == slot_index
    ]
    if config_limit is not None:
        assigned_configs = assigned_configs[:config_limit]
    return assigned_configs


def has_hidden_path_part(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts)


def config_display_name(config_path: Path, config_dir: Path) -> str:
    try:
        return config_path.relative_to(config_dir).as_posix()
    except ValueError:
        return config_path.name


def rotation_positions(current_position: int, config_count: int) -> list[int]:
    if config_count <= 0:
        return []
    return random.sample(range(config_count), config_count)


def least_recently_failed_positions(
    positions: list[int],
    configs: list[Path],
    config_last_failed_at: dict[Path, float],
) -> list[int]:
    position_order = {position: index for index, position in enumerate(positions)}
    return sorted(
        positions,
        key=lambda position: (
            configs[position] in config_last_failed_at,
            config_last_failed_at.get(configs[position], 0.0),
            position_order[position],
        ),
    )


def normalize_wireguard_config(text: str) -> str:
    normalized_lines = [normalize_wireguard_config_line(line) for line in text.splitlines()]
    return "\n".join(line for line in normalized_lines if line is not None) + "\n"


def wireguard_config_summary(text: str) -> dict[str, list[str]]:
    keys = {"address", "dns", "allowedips", "endpoint", "persistentkeepalive"}
    summary: dict[str, list[str]] = {key: [] for key in keys}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";", "[")) or "=" not in stripped:
            continue
        key, _separator, value = stripped.partition("=")
        normalized_key = key.strip().lower()
        if normalized_key in keys:
            summary[normalized_key].append(value.strip())
    return {key: values for key, values in sorted(summary.items()) if values}


def normalize_wireguard_config_line(line: str) -> str | None:
    if "=" not in line or line.lstrip().startswith(("#", ";", "[")):
        return line

    key, separator, value = line.partition("=")
    value_body, comment = split_inline_comment(value)
    parts = value_body.split(",")
    kept_parts: list[str] = []
    changed = False

    for part in parts:
        stripped = part.strip()
        if not stripped:
            kept_parts.append(part)
            continue
        if is_ipv6_address_like(stripped):
            changed = True
            continue
        kept_parts.append(part)

    if not changed:
        return line

    kept_values = [part.strip() for part in kept_parts if part.strip()]
    if not kept_values:
        return None
    return f"{key}{separator} {', '.join(kept_values)}{comment}"


def split_inline_comment(value: str) -> tuple[str, str]:
    for index, character in enumerate(value):
        if character in ("#", ";") and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip(), f" {value[index:].strip()}"
    return value, ""


def is_ipv6_address_like(value: str) -> bool:
    value = value.strip()
    if value.startswith("["):
        host, separator, _port = value[1:].partition("]")
        if separator and is_ip_version(host, 6):
            return True
    try:
        return ipaddress.ip_interface(value).version == 6
    except ValueError:
        pass
    try:
        return ipaddress.ip_network(value, strict=False).version == 6
    except ValueError:
        pass
    return is_ip_version(value, 6)


def is_ip_version(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


class ProxySupervisor:
    def __init__(self) -> None:
        self.source = os.environ.get("PROXY_SOURCE", "local")
        self.slot = os.environ.get("PROXY_SLOT", "00")
        self.slot_index = parse_int(
            os.environ.get("PROXY_SLOT_INDEX", self.slot),
            name="PROXY_SLOT_INDEX",
            minimum=0,
        )
        self.slot_count = env_int("PROXY_SLOTS", 1, minimum=1)
        if self.slot_index >= self.slot_count:
            raise RuntimeError(
                f"PROXY_SLOT_INDEX must be less than PROXY_SLOTS: "
                f"{self.slot_index} >= {self.slot_count}"
            )

        config_limit = env_int("PROXY_CONFIG_LIMIT", 0, minimum=0)
        self.config_limit = config_limit if config_limit > 0 else None
        self.config_dir = Path(os.environ.get("CONFIG_DIR", "/configs"))
        self.proxy_port = env_int("PROXY_PORT", DEFAULT_PROXY_PORT, minimum=1)
        self.admin_port = env_int("ADMIN_PORT", DEFAULT_ADMIN_PORT, minimum=1)
        self.wg_if = os.environ.get("WG_IF", "wg0")
        self.runtime_config = Path(f"/run/{self.wg_if}.conf")
        self.healthcheck_url = os.environ.get(
            "HEALTHCHECK_URL",
            DEFAULT_HEALTHCHECK_URL,
        )
        self.tunnel_healthcheck_url = os.environ.get(
            "TUNNEL_HEALTHCHECK_URL",
            DEFAULT_TUNNEL_HEALTHCHECK_URL,
        )
        self.healthcheck_connect_timeout = env_int(
            "HEALTHCHECK_CONNECT_TIMEOUT",
            DEFAULT_HEALTHCHECK_CONNECT_TIMEOUT,
            minimum=1,
        )
        self.healthcheck_max_time = env_int(
            "HEALTHCHECK_MAX_TIME",
            DEFAULT_HEALTHCHECK_MAX_TIME,
            minimum=1,
        )
        self.proxy_drain_timeout = env_int(
            "PROXY_DRAIN_TIMEOUT",
            DEFAULT_PROXY_DRAIN_TIMEOUT,
            minimum=0,
        )
        self.tinyproxy_log_level = os.environ.get("TINYPROXY_LOG_LEVEL", "Info")
        self.tinyproxy_conf = Path("/tmp/tinyproxy.conf")

        self.assigned_configs = self._discover_assigned_configs()
        if not self.assigned_configs:
            raise RuntimeError(
                f"no WireGuard configs assigned to source={self.source!r} "
                f"slot={self.slot!r}"
            )

        self.state_lock = threading.RLock()
        self.rotation_lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.server: ThreadingHTTPServer | None = None
        self.tinyproxy_process: subprocess.Popen[str] | None = None
        self.tinyproxy_expected_stop = False

        self.state = "starting"
        self.health_status = "unknown"
        self.active_config: Path | None = None
        self.active_config_started_at: str | None = None
        self.current_config_position = -1
        self.rotation_count = 0
        self.last_rotation_at: str | None = None
        self.last_rotation_reason: str | None = None
        self.last_rotation_error: str | None = None
        self.configs_tried: list[str] = []
        self.config_last_failed_at: dict[Path, float] = {}

    def serve(self) -> None:
        self._install_signal_handlers()
        self._validate_runtime()
        self._start_first_ready_config()

        self.server = ThreadingHTTPServer(("0.0.0.0", self.admin_port), handler(self))
        log(
            "admin listening "
            f"source={self.source} slot={self.slot} port={self.admin_port}"
        )
        try:
            self.server.serve_forever()
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self.shutdown_event.set()
        with self.state_lock:
            self.state = "stopping"
        self._stop_tinyproxy()
        self._wg_down()
        self._remove_egress_rules()

    def status_response(self) -> dict[str, Any]:
        with self.state_lock:
            active_config = (
                config_display_name(self.active_config, self.config_dir)
                if self.active_config is not None
                else None
            )
            return {
                "source": self.source,
                "slot": self.slot,
                "state": self.state,
                "active_config": active_config,
                "active_config_started_at": self.active_config_started_at,
                "rotation_count": self.rotation_count,
                "last_rotation_at": self.last_rotation_at,
                "last_rotation_reason": self.last_rotation_reason,
                "last_rotation_error": self.last_rotation_error,
                "health_status": self.health_status,
                "configs_assigned": len(self.assigned_configs),
                "configs_tried": list(self.configs_tried),
                "configs_dead": [],
            }

    def rotate(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.rotation_lock.acquire(blocking=False):
            raise RotationBusy("slot is already rotating")

        started_at = time.monotonic()
        reason = str(payload.get("reason") or "manual")
        previous_config = self.active_config
        previous_name = (
            config_display_name(previous_config, self.config_dir)
            if previous_config is not None
            else None
        )
        positions = rotation_positions(
            self.current_config_position,
            len(self.assigned_configs),
        )
        if reason == "proxy_cooldown" and previous_config is not None:
            self.config_last_failed_at[previous_config] = started_at
        positions = least_recently_failed_positions(
            positions,
            self.assigned_configs,
            self.config_last_failed_at,
        )
        next_name = config_display_name(
            self.assigned_configs[positions[0]],
            self.config_dir,
        )
        attempted_names: list[str] = []

        try:
            with self.state_lock:
                self.state = "rotating"
                self.health_status = "unknown"
                self.last_rotation_reason = reason
                self.last_rotation_error = None
            log(
                "rotate requested "
                f"source={self.source} slot={self.slot} "
                f"reason={reason!r} previous={previous_name!r} next={next_name!r}"
            )
            self._reject_new_proxy_connections()
            self._wait_for_proxy_connections_to_drain()
            last_error: BaseException | None = None

            for position in positions:
                name = config_display_name(
                    self.assigned_configs[position],
                    self.config_dir,
                )
                attempted_names.append(name)
                try:
                    self._stop_tinyproxy()
                    self._wg_down()
                    self._activate_config(position)
                    self._run_tunnel_healthcheck()
                    self._start_tinyproxy()
                    self.run_healthcheck()
                except BaseException as exc:
                    last_error = exc
                    self.config_last_failed_at[self.assigned_configs[position]] = (
                        time.monotonic()
                    )
                    with self.state_lock:
                        self.health_status = "failed"
                        self.last_rotation_error = str(exc)
                    log(
                        "rotate config failed "
                        f"source={self.source} slot={self.slot} config={name!r} "
                        f"error={exc}"
                    )
                    self._stop_tinyproxy()
                    self._wg_down()
                    continue

                with self.state_lock:
                    self.state = "ready"
                    self.rotation_count += 1
                    self.last_rotation_at = utc_now()
                    self.last_rotation_error = None
                elapsed_ms = int((time.monotonic() - started_at) * 1000)
                log(
                    "rotate ok "
                    f"source={self.source} slot={self.slot} previous={previous_name!r} "
                    f"active={name!r} attempted={attempted_names!r} "
                    f"elapsed_ms={elapsed_ms}"
                )
                return {
                    "ok": True,
                    "source": self.source,
                    "slot": self.slot,
                    "previous_config": previous_name,
                    "active_config": name,
                    "health_status": self.health_status,
                }

            raise RuntimeError("no assigned WireGuard config passed rotation") from last_error
        except BaseException as exc:
            with self.state_lock:
                self.state = "unhealthy"
                self.health_status = "failed"
                self.last_rotation_error = str(exc)
            log(
                "rotate failed "
                f"source={self.source} slot={self.slot} previous={previous_name!r} "
                f"attempted={attempted_names!r} error={exc}"
            )
            raise
        finally:
            self._allow_new_proxy_connections()
            self.rotation_lock.release()

    def run_healthcheck(self) -> dict[str, Any]:
        self._run_curl_healthcheck(
            [
                "--proxy",
                f"http://127.0.0.1:{self.proxy_port}",
            ],
            failure_prefix="proxy health probe failed",
        )
        with self.state_lock:
            self.health_status = "ready"
        return {
            "ok": True,
            "source": self.source,
            "slot": self.slot,
            "health_status": self.health_status,
            "active_config": self.status_response()["active_config"],
        }

    def _run_tunnel_healthcheck(self) -> None:
        self._run_curl_healthcheck(
            [
                "--interface",
                self.wg_if,
            ],
            failure_prefix="tunnel health probe failed",
            url=self.tunnel_healthcheck_url,
        )

    def _run_curl_healthcheck(
        self,
        extra_args: list[str],
        *,
        failure_prefix: str,
        url: str | None = None,
    ) -> None:
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            *extra_args,
            "--connect-timeout",
            str(self.healthcheck_connect_timeout),
            "--max-time",
            str(self.healthcheck_max_time),
            url or self.healthcheck_url,
        ]
        result = run_command(
            command,
            check=False,
            timeout=self.healthcheck_max_time + 5,
        )
        if result.returncode != 0:
            with self.state_lock:
                self.health_status = "failed"
            detail = result.output.strip() or "curl returned non-zero"
            self._log_tunnel_diagnostics(failure_prefix)
            raise HealthcheckError(f"{failure_prefix}: {detail}")

    def _log_tunnel_diagnostics(self, context: str) -> None:
        diagnostics = [
            ("wg_show", ["wg", "show", self.wg_if]),
            ("ip_addr", ["ip", "-brief", "addr", "show", self.wg_if]),
            ("ip_route", ["ip", "route"]),
            ("ip_route_get_healthcheck", ["ip", "route", "get", "1.1.1.1"]),
        ]
        for name, command in diagnostics:
            result = run_command(command, check=False, timeout=5)
            output = result.output.strip() or "<empty>"
            log(
                f"diagnostic {context} {name} "
                f"returncode={result.returncode} output={output!r}"
            )

    def _discover_assigned_configs(self) -> list[Path]:
        if not self.config_dir.is_dir():
            raise RuntimeError(f"config directory does not exist: {self.config_dir}")
        all_configs = sorted(
            (
                path
                for path in self.config_dir.rglob("*.conf")
                if not has_hidden_path_part(path.relative_to(self.config_dir))
            ),
            key=lambda path: path.relative_to(self.config_dir).as_posix(),
        )
        return assigned_config_paths(
            all_configs,
            slot_count=self.slot_count,
            slot_index=self.slot_index,
            config_limit=self.config_limit,
        )

    def _validate_runtime(self) -> None:
        if not Path("/dev/net/tun").is_char_device():
            raise RuntimeError(
                "missing /dev/net/tun; run with --device /dev/net/tun:/dev/net/tun"
            )

    def _start_first_ready_config(self) -> None:
        last_error: BaseException | None = None
        for position, config_path in enumerate(self.assigned_configs):
            name = config_display_name(config_path, self.config_dir)
            try:
                with self.state_lock:
                    self.state = "starting"
                    self.health_status = "unknown"
                self._stop_tinyproxy()
                self._wg_down()
                self._activate_config(position)
                self._run_tunnel_healthcheck()
                self._start_tinyproxy()
                self.run_healthcheck()
                with self.state_lock:
                    self.state = "ready"
                    self.last_rotation_error = None
                log(
                    "ready "
                    f"source={self.source} slot={self.slot} active={name!r} "
                    f"configs_assigned={len(self.assigned_configs)}"
                )
                return
            except BaseException as exc:
                last_error = exc
                with self.state_lock:
                    self.health_status = "failed"
                    self.last_rotation_error = str(exc)
                log(
                    "initial config failed "
                    f"source={self.source} slot={self.slot} config={name!r} "
                    f"error={exc}"
                )
                self._stop_tinyproxy()
                self._wg_down()
        raise RuntimeError("no assigned WireGuard config passed healthcheck") from last_error

    def _activate_config(self, position: int) -> None:
        config_path = self.assigned_configs[position]
        display_name = config_display_name(config_path, self.config_dir)
        config_text = config_path.read_text(encoding="utf-8")
        normalized_config = normalize_wireguard_config(config_text)
        self.runtime_config.parent.mkdir(parents=True, exist_ok=True)
        self.runtime_config.write_text(
            normalized_config,
            encoding="utf-8",
        )
        self.runtime_config.chmod(0o600)
        with self.state_lock:
            self.configs_tried.append(display_name)
        log(
            f"bringing up {self.wg_if} config={display_name!r} "
            f"summary={wireguard_config_summary(normalized_config)!r}"
        )
        run_command(["wg-quick", "up", str(self.runtime_config)])
        self._install_egress_rules()
        with self.state_lock:
            self.active_config = config_path
            self.active_config_started_at = utc_now()
            self.current_config_position = position

    def _wg_down(self) -> None:
        if run_command(["ip", "link", "show", self.wg_if], check=False).returncode != 0:
            return
        log(f"bringing down {self.wg_if}")
        if self.runtime_config.exists():
            result = run_command(["wg-quick", "down", str(self.runtime_config)], check=False)
            if result.returncode == 0:
                return
            log(f"wg-quick down failed, deleting link directly: {result.output.strip()}")
        run_command(["ip", "link", "delete", self.wg_if], check=False)

    def _install_egress_rules(self) -> None:
        chain = "WG_PROXY_OUTPUT"
        log("installing container-local egress rules")
        run_command(["iptables", "-N", chain], check=False)
        run_command(["iptables", "-F", chain])
        while run_command(["iptables", "-D", "OUTPUT", "-j", chain], check=False).returncode == 0:
            pass
        run_command(["iptables", "-I", "OUTPUT", "1", "-j", chain])
        run_command(["iptables", "-A", chain, "-o", "lo", "-j", "ACCEPT"])
        run_command(
            [
                "iptables",
                "-A",
                chain,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        run_command(["iptables", "-A", chain, "-o", self.wg_if, "-j", "ACCEPT"])
        fwmark = run_command(["wg", "show", self.wg_if, "fwmark"], check=False).output.strip()
        if fwmark and fwmark != "off":
            run_command(["iptables", "-A", chain, "-m", "mark", "--mark", fwmark, "-j", "ACCEPT"])
        run_command(["iptables", "-A", chain, "-j", "REJECT"])

    def _remove_egress_rules(self) -> None:
        chain = "WG_PROXY_OUTPUT"
        while run_command(["iptables", "-D", "OUTPUT", "-j", chain], check=False).returncode == 0:
            pass
        run_command(["iptables", "-F", chain], check=False)
        run_command(["iptables", "-X", chain], check=False)

    def _proxy_reject_rule(self) -> list[str]:
        return proxy_reject_rule(self.proxy_port)

    def _reject_new_proxy_connections(self) -> None:
        rule = self._proxy_reject_rule()
        while run_command(["iptables", "-D", *rule], check=False).returncode == 0:
            pass
        log(f"rejecting new proxy connections on port {self.proxy_port}")
        run_command(["iptables", "-I", *rule])

    def _allow_new_proxy_connections(self) -> None:
        rule = self._proxy_reject_rule()
        while run_command(["iptables", "-D", *rule], check=False).returncode == 0:
            pass

    def _active_proxy_connections(self) -> int:
        result = run_command(
            [
                "ss",
                "-Htan",
                "state",
                "established",
                "sport",
                "=",
                f":{self.proxy_port}",
            ],
            check=False,
        )
        return count_ss_connections(result.output)

    def _wait_for_proxy_connections_to_drain(self) -> None:
        deadline = time.monotonic() + self.proxy_drain_timeout
        while True:
            active_connections = self._active_proxy_connections()
            if active_connections == 0:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log(
                    "proxy drain timeout "
                    f"active_connections={active_connections} "
                    f"timeout_seconds={self.proxy_drain_timeout}"
                )
                return
            time.sleep(min(0.25, remaining))

    def _start_tinyproxy(self) -> None:
        self._write_tinyproxy_config()
        log(f"starting HTTP proxy on 0.0.0.0:{self.proxy_port}")
        self.tinyproxy_expected_stop = False
        process = subprocess.Popen(
            ["tinyproxy", "-d", "-c", str(self.tinyproxy_conf)],
            text=True,
        )
        self.tinyproxy_process = process
        self._allow_new_proxy_connections()
        threading.Thread(
            target=self._monitor_tinyproxy,
            args=(process,),
            daemon=True,
        ).start()

    def _stop_tinyproxy(self) -> None:
        process = self.tinyproxy_process
        if process is None or process.poll() is not None:
            self.tinyproxy_process = None
            return
        log("stopping tinyproxy")
        self.tinyproxy_expected_stop = True
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        finally:
            if self.tinyproxy_process is process:
                self.tinyproxy_process = None

    def _monitor_tinyproxy(self, process: subprocess.Popen[str]) -> None:
        returncode = process.wait()
        if self.shutdown_event.is_set():
            return
        if self.tinyproxy_process is process and not self.tinyproxy_expected_stop:
            log(f"tinyproxy exited unexpectedly returncode={returncode}")
            os._exit(1)

    def _write_tinyproxy_config(self) -> None:
        self.tinyproxy_conf.write_text(
            "\n".join(
                [
                    "User tinyproxy",
                    "Group tinyproxy",
                    f"Port {self.proxy_port}",
                    "Listen 0.0.0.0",
                    "Timeout 600",
                    "MaxClients 100",
                    f"LogLevel {self.tinyproxy_log_level}",
                    'PidFile "/tmp/tinyproxy.pid"',
                    "ConnectPort 443",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def _install_signal_handlers(self) -> None:
        def handle_signal(signum: int, _frame: object) -> None:
            log(f"received signal {signum}, shutting down")
            if self.server is not None:
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self.shutdown_event.set()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)


def read_json_body(request: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(request.headers.get("Content-Length") or "0")
    if length > MAX_REQUEST_BYTES:
        raise ValueError("request body is too large")
    if length == 0:
        return {}
    body = request.rfile.read(length)
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("request body must be a JSON object")
    return parsed


def handler(supervisor: ProxySupervisor) -> type[BaseHTTPRequestHandler]:
    class ProxyAdminHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/status":
                self._send_json(404, {"ok": False, "error": "not found"})
                return
            self._send_json(200, supervisor.status_response())

        def do_POST(self) -> None:
            if self.path == "/healthcheck":
                self._handle_healthcheck()
                return
            if self.path == "/rotate":
                self._handle_rotate()
                return
            self._send_json(404, {"ok": False, "error": "not found"})

        def log_message(self, format: str, *args: object) -> None:
            log(f"admin {self.address_string()} {format % args}")

        def _handle_healthcheck(self) -> None:
            try:
                response = supervisor.run_healthcheck()
            except BaseException as exc:
                self._send_json(
                    500,
                    {
                        "ok": False,
                        "source": supervisor.source,
                        "slot": supervisor.slot,
                        "health_status": "failed",
                        "error": str(exc),
                    },
                )
                return
            self._send_json(200, response)

        def _handle_rotate(self) -> None:
            try:
                payload = read_json_body(self)
                response = supervisor.rotate(payload)
            except RotationBusy as exc:
                self._send_json(409, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except BaseException as exc:
                self._send_json(
                    500,
                    {
                        "ok": False,
                        "source": supervisor.source,
                        "slot": supervisor.slot,
                        "health_status": "failed",
                        "error": str(exc),
                    },
                )
                return
            self._send_json(200, response)

        def _send_json(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ProxyAdminHandler

def main() -> None:
    try:
        ProxySupervisor().serve()
    except BaseException as exc:
        log(f"fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
