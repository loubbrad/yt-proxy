from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location("yt_proxy_spawn", ROOT / "spawn.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load spawn.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SpawnTests(unittest.TestCase):
    def make_routes(self, module, root: Path):
        config_dir = root / "configs" / "proton" / "route-1"
        config_dir.mkdir(parents=True)
        for name in ("de.conf", "nl.conf"):
            (config_dir / name).write_text("[Interface]\nAddress = 10.0.0.2/32\n")
        fleet = {
            "host_proxy_port_start": 9000,
            "host_admin_port_start": 10000,
            "routes": [
                {
                    "name": "Proton 1",
                    "config_dir": "proton/route-1",
                }
            ],
        }
        return module.build_routes(fleet, root / "configs")

    def test_route_is_one_container_with_rotation_alternatives(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            routes = self.make_routes(module, Path(directory))

        self.assertEqual(len(routes), 1)
        self.assertEqual(len(routes[0].configs), 2)
        self.assertEqual(routes[0].host_proxy_port, 9000)
        self.assertEqual(routes[0].host_admin_port, 10000)

    def test_compose_publishes_proxy_and_admin_to_loopback(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            routes = self.make_routes(module, Path(directory))
            compose = yaml.safe_load(
                module.render_compose(routes, "127.0.0.1", None)
            )

        service = compose["services"]["proxy-proton-1"]
        self.assertEqual(
            service["ports"],
            ["127.0.0.1:9000:8888", "127.0.0.1:10000:8889"],
        )
        self.assertNotIn("networks", service)

    def test_named_network_is_external_and_attached(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            routes = self.make_routes(module, Path(directory))
            compose = yaml.safe_load(
                module.render_compose(routes, "127.0.0.1", "my-app-net")
            )

        self.assertEqual(
            compose["networks"]["proxy_network"],
            {"name": "my-app-net", "external": True},
        )
        self.assertEqual(
            compose["services"]["proxy-proton-1"]["networks"],
            ["proxy_network"],
        )

    def test_endpoint_modes_do_not_duplicate_routes(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            routes = self.make_routes(module, Path(directory))

        host = module.endpoint_rows(routes, "host")
        docker = module.endpoint_rows(routes, "docker")
        self.assertEqual(host[0]["proxy_url"], "http://127.0.0.1:9000")
        self.assertEqual(host[0]["admin_url"], "http://127.0.0.1:10000")
        self.assertEqual(docker[0]["proxy_url"], "http://proxy-proton-1:8888")
        self.assertEqual(docker[0]["admin_url"], "http://proxy-proton-1:8889")

    def test_overlapping_port_ranges_are_rejected(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / "configs" / "a"
            config_dir.mkdir(parents=True)
            (config_dir / "one.conf").write_text("test")
            fleet = {
                "host_proxy_port_start": 8888,
                "host_admin_port_start": 8888,
                "routes": [{"name": "a", "config_dir": "a"}],
            }
            with self.assertRaises(SystemExit):
                module.build_routes(fleet, root / "configs")


if __name__ == "__main__":
    unittest.main()
