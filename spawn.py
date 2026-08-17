#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml


PROXY_PORT = 8888
ADMIN_PORT = 8889
DEFAULT_PROJECT = "yt-proxy"
DEFAULT_PROXY_PORT_START = 8888
DEFAULT_ADMIN_PORT_START = 9888


@dataclass(frozen=True)
class Route:
    name: str
    slug: str
    config_dir: Path
    configs: tuple[Path, ...]
    host_proxy_port: int
    host_admin_port: int


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Run rotating WireGuard HTTP proxies in Docker."
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("up", "generate", "plan", "ps", "logs", "down"),
        default="up",
    )
    parser.add_argument("--fleet-file", type=Path, default=root / "fleet.yaml")
    parser.add_argument("--config-root", type=Path, default=root / "configs")
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=root / "compose.generated.yaml",
    )
    parser.add_argument("--project-name", default=DEFAULT_PROJECT)
    parser.add_argument(
        "--bind-host",
        default="127.0.0.1",
        help="Host address for published proxy and admin ports (default: loopback).",
    )
    parser.add_argument("--host-proxy-port-start", type=int)
    parser.add_argument("--host-admin-port-start", type=int)
    parser.add_argument(
        "--network",
        help="Optional named Docker network for clients running in containers.",
    )
    parser.add_argument(
        "--attach-container",
        action="append",
        default=[],
        metavar="CONTAINER",
        help="Attach an existing container to --network; may be repeated.",
    )
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument(
        "--endpoint-mode",
        choices=("host", "docker"),
        default="host",
        help="Address form written by --output (default: host).",
    )
    args, compose_args = parser.parse_known_args()
    if compose_args and args.command not in ("ps", "logs"):
        parser.error(f"unrecognized arguments: {' '.join(compose_args)}")
    if args.attach_container and not args.network:
        parser.error("--attach-container requires --network")
    if args.endpoint_mode == "docker" and not args.network:
        parser.error("--endpoint-mode docker requires --network")
    args.compose_args = compose_args
    return args


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parent
    compose_file = args.compose_file.expanduser().resolve()

    if args.command == "down":
        reject_output(args)
        run_compose(root, compose_file, args.project_name, ["down", "--remove-orphans"])
        return

    if args.command in ("ps", "logs"):
        reject_output(args)
        run_compose(
            root,
            compose_file,
            args.project_name,
            [args.command, *args.compose_args],
        )
        return

    fleet = load_fleet(args.fleet_file.expanduser().resolve())
    routes = build_routes(
        fleet,
        args.config_root.expanduser().resolve(),
        proxy_port_override=args.host_proxy_port_start,
        admin_port_override=args.host_admin_port_start,
    )
    compose_text = render_compose(routes, args.bind_host, args.network)

    if args.command == "plan":
        reject_output(args)
        print_plan(routes)
        return

    write_text_atomic(compose_file, compose_text)
    write_endpoints(args.output, routes, args.endpoint_mode)
    if args.command == "generate":
        print(compose_file)
        return

    if args.network:
        ensure_network(args.network)
    run_compose(
        root,
        compose_file,
        args.project_name,
        ["up", "-d", "--build", "--remove-orphans"],
    )
    for container in args.attach_container:
        connect_container(args.network, container)
    print_endpoints(routes, args.endpoint_mode)


def load_fleet(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise SystemExit(
            f"Fleet file not found: {path}\n"
            "Copy fleet.example.yaml to fleet.yaml and edit it first."
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"Fleet file must contain a YAML mapping: {path}")
    return data


def build_routes(
    fleet: dict[str, object],
    config_root: Path,
    *,
    proxy_port_override: int | None = None,
    admin_port_override: int | None = None,
) -> list[Route]:
    proxy_port = int_value(
        proxy_port_override,
        fleet.get("host_proxy_port_start"),
        DEFAULT_PROXY_PORT_START,
        name="host_proxy_port_start",
        minimum=1,
    )
    admin_port = int_value(
        admin_port_override,
        fleet.get("host_admin_port_start"),
        DEFAULT_ADMIN_PORT_START,
        name="host_admin_port_start",
        minimum=1,
    )
    raw_routes = fleet.get("routes")
    if not isinstance(raw_routes, list) or not raw_routes:
        raise SystemExit("fleet routes must be a non-empty list")

    routes: list[Route] = []
    seen_names: set[str] = set()
    for index, raw in enumerate(raw_routes):
        if not isinstance(raw, dict):
            raise SystemExit(f"route {index} must be a mapping")
        name = raw.get("name")
        config_dir_name = raw.get("config_dir")
        if not isinstance(name, str) or not name.strip():
            raise SystemExit(f"route {index} requires a non-empty name")
        if not isinstance(config_dir_name, str) or not config_dir_name.strip():
            raise SystemExit(f"route {name!r} requires a non-empty config_dir")
        slug = slugify(name)
        if not slug or slug in seen_names:
            raise SystemExit(f"route name is invalid or duplicated: {name!r}")
        seen_names.add(slug)
        config_dir = (config_root / config_dir_name).resolve()
        configs = discover_configs(config_dir)
        routes.append(
            Route(
                name=name,
                slug=slug,
                config_dir=config_dir,
                configs=configs,
                host_proxy_port=proxy_port + index,
                host_admin_port=admin_port + index,
            )
        )
    validate_ports(routes)
    return routes


def int_value(
    override: int | None,
    configured: object,
    default: int,
    *,
    name: str,
    minimum: int,
) -> int:
    value: object = override if override is not None else configured
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int):
        raise SystemExit(f"{name} must be an integer")
    if value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}")
    return value


def discover_configs(config_dir: Path) -> tuple[Path, ...]:
    if not config_dir.is_dir():
        raise SystemExit(f"Config directory does not exist: {config_dir}")
    configs = tuple(
        sorted(
            (
                path.resolve()
                for path in config_dir.rglob("*.conf")
                if not any(
                    part.startswith(".")
                    for part in path.relative_to(config_dir).parts
                )
            ),
            key=lambda path: path.relative_to(config_dir).as_posix(),
        )
    )
    if not configs:
        raise SystemExit(f"No .conf files found in: {config_dir}")
    return configs


def validate_ports(routes: list[Route]) -> None:
    ports = [route.host_proxy_port for route in routes]
    ports.extend(route.host_admin_port for route in routes)
    if len(ports) != len(set(ports)):
        raise SystemExit("host proxy and admin port ranges overlap")
    if any(port > 65535 for port in ports):
        raise SystemExit("host port must not exceed 65535")


def render_compose(routes: list[Route], bind_host: str, network: str | None) -> str:
    services: dict[str, object] = {}
    for route in routes:
        service: dict[str, object] = {
            "build": ".",
            "image": "yt-proxy:local",
            "cap_add": ["NET_ADMIN"],
            "devices": ["/dev/net/tun:/dev/net/tun"],
            "volumes": [f"{route.config_dir}:/configs:ro"],
            "environment": {
                "PROXY_SOURCE": route.name,
                "PROXY_SLOT": "00",
                "PROXY_SLOT_INDEX": "0",
                "PROXY_SLOTS": "1",
                "PROXY_CONFIG_LIMIT": "0",
                "CONFIG_DIR": "/configs",
                "PROXY_PORT": str(PROXY_PORT),
                "ADMIN_PORT": str(ADMIN_PORT),
            },
            "ports": [
                f"{bind_host}:{route.host_proxy_port}:{PROXY_PORT}",
                f"{bind_host}:{route.host_admin_port}:{ADMIN_PORT}",
            ],
            "healthcheck": {
                "test": ["CMD", "curl", "-fsS", f"http://127.0.0.1:{ADMIN_PORT}/status"],
                "interval": "10s",
                "timeout": "3s",
                "retries": 3,
                "start_period": "20s",
            },
            "restart": "unless-stopped",
            "sysctls": {
                "net.ipv4.conf.all.src_valid_mark": "1",
                "net.ipv6.conf.all.disable_ipv6": "1",
                "net.ipv6.conf.default.disable_ipv6": "1",
            },
        }
        if network:
            service["networks"] = ["proxy_network"]
        services[service_name(route)] = service

    document: dict[str, object] = {"services": services}
    if network:
        document["networks"] = {
            "proxy_network": {"name": network, "external": True}
        }
    return "# Generated by spawn.py. Do not edit.\n" + yaml.safe_dump(
        document,
        sort_keys=False,
    )


def endpoint_rows(routes: list[Route], mode: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for route in routes:
        if mode == "host":
            proxy_url = f"http://127.0.0.1:{route.host_proxy_port}"
            admin_url = f"http://127.0.0.1:{route.host_admin_port}"
        else:
            proxy_url = f"http://{service_name(route)}:{PROXY_PORT}"
            admin_url = f"http://{service_name(route)}:{ADMIN_PORT}"
        rows.append(
            {
                "name": route.name,
                "proxy_url": proxy_url,
                "admin_url": admin_url,
            }
        )
    return rows


def write_endpoints(path: Path | None, routes: list[Route], mode: str) -> None:
    if path is None:
        return
    text = yaml.safe_dump({"proxies": endpoint_rows(routes, mode)}, sort_keys=False)
    write_text_atomic(path.expanduser().resolve(), text)


def print_endpoints(routes: list[Route], mode: str) -> None:
    for row in endpoint_rows(routes, mode):
        print(f"{row['name']}: {row['proxy_url']}  admin={row['admin_url']}")


def print_plan(routes: list[Route]) -> None:
    for route in routes:
        print(
            "\t".join(
                (
                    route.name,
                    str(route.host_proxy_port),
                    str(route.host_admin_port),
                    str(len(route.configs)),
                    str(route.config_dir),
                )
            )
        )


def service_name(route: Route) -> str:
    return f"proxy-{route.slug}"


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.strip().lower()).strip("-")


def ensure_network(network: str) -> None:
    result = run(["docker", "network", "inspect", network], check=False)
    if result.returncode == 0:
        return
    run(["docker", "network", "create", network])


def connect_container(network: str | None, container: str) -> None:
    if network is None:
        raise AssertionError("network required")
    result = run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"Container does not exist: {container}")
    networks = json.loads(result.stdout)
    if network not in networks:
        run(["docker", "network", "connect", network, container])


def run_compose(root: Path, compose_file: Path, project: str, args: list[str]) -> None:
    if not compose_file.is_file() and args[0] != "up":
        raise SystemExit(f"Generated Compose file not found: {compose_file}")
    run(
        ["docker", "compose", "-p", project, "-f", str(compose_file), *args],
        cwd=root,
    )


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise SystemExit(f"Command failed: {' '.join(command)}\n{detail}")
    return completed


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def reject_output(args: argparse.Namespace) -> None:
    if args.output is not None:
        raise SystemExit("--output is only supported by up and generate")


if __name__ == "__main__":
    main()
