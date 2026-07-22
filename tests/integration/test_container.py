"""Checks for the production image configuration tied to pinned SearXNG."""

from pathlib import Path
from unittest import TestCase

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ContainerConfigurationTest(TestCase):
    def test_fresh_install_keeps_builtins_and_enables_access(self) -> None:
        upstream = yaml.safe_load((ROOT / ".searxng/searx/settings.yml").read_text())
        image = yaml.safe_load((ROOT / "container/settings.template.yml").read_text())

        self.assertEqual(
            set(upstream["plugins"]), set(image["plugins"]) - {"searxng_access.plugin.SXNGPlugin"}
        )
        self.assertTrue(image["plugins"]["searxng_access.plugin.SXNGPlugin"]["active"])
        self.assertIn("json", image["search"]["formats"])
