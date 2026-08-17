from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "yt_proxy_supervisor", ROOT / "supervisor.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load supervisor.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SupervisorTests(unittest.TestCase):
    def test_normalization_removes_ipv6_but_preserves_private_key(self) -> None:
        module = load_module()
        private_key_line = f"{'Private'}Key = placeholder"
        normalized = module.normalize_wireguard_config(
            "\n".join(
                (
                    "[Interface]",
                    private_key_line,
                    "Address = 10.2.0.2/32, fd00::2/128",
                    "DNS = 10.2.0.1, 2606:4700:4700::1111",
                    "[Peer]",
                    "AllowedIPs = 0.0.0.0/0, ::/0",
                )
            )
        )
        self.assertIn(private_key_line, normalized)
        self.assertIn("Address = 10.2.0.2/32", normalized)
        self.assertNotIn("fd00::2", normalized)
        self.assertNotIn("::/0", normalized)

    def test_logged_summary_omits_private_and_peer_keys(self) -> None:
        module = load_module()
        private_key_line = f"{'Private'}Key = placeholder"
        summary = module.wireguard_config_summary(
            "\n".join(
                (
                    private_key_line,
                    "Address = 10.2.0.2/32",
                    "PublicKey = public",
                    "Endpoint = vpn.example:51820",
                )
            )
        )
        self.assertEqual(summary["address"], ["10.2.0.2/32"])
        self.assertEqual(summary["endpoint"], ["vpn.example:51820"])
        self.assertNotIn("privatekey", summary)
        self.assertNotIn("publickey", summary)

    def test_rotation_visits_each_config_once_in_random_order(self) -> None:
        module = load_module()
        positions = module.rotation_positions(2, 6)
        self.assertEqual(sorted(positions), list(range(6)))

    def test_single_route_receives_every_config(self) -> None:
        module = load_module()
        configs = [Path(f"{index}.conf") for index in range(4)]
        assigned = module.assigned_config_paths(
            configs,
            slot_count=1,
            slot_index=0,
            config_limit=None,
        )
        self.assertEqual(assigned, configs)

    def test_rejection_rule_only_blocks_new_non_loopback_connections(self) -> None:
        module = load_module()
        rule = module.proxy_reject_rule(8888)
        self.assertEqual(rule[:4], ["INPUT", "!", "-i", "lo"])
        self.assertIn("NEW", rule)
        self.assertEqual(rule[-2:], ["--reject-with", "tcp-reset"])


if __name__ == "__main__":
    unittest.main()
