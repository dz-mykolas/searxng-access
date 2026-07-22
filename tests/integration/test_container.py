"""Checks for the production image configuration tied to pinned SearXNG."""

from pathlib import Path
from unittest import TestCase

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ContainerConfigurationTest(TestCase):
    def test_builder_includes_the_declared_license(self) -> None:
        dockerignore = (ROOT / ".dockerignore").read_text().splitlines()
        containerfile = (ROOT / "Containerfile").read_text()

        self.assertIn("!LICENSE", dockerignore)
        self.assertIn("COPY LICENSE README.md pyproject.toml uv.lock ./", containerfile)

    def test_runtime_uses_paths_available_in_the_upstream_image(self) -> None:
        containerfile = (ROOT / "Containerfile").read_text()

        self.assertIn("source=/uv,target=/tmp/uv", containerfile)
        self.assertIn(
            "ln -s /usr/local/searxng/.venv/bin/searxng-access /usr/bin/searxng-access",
            containerfile,
        )

    def test_fresh_install_keeps_builtins_and_enables_access(self) -> None:
        upstream = yaml.safe_load((ROOT / ".searxng/searx/settings.yml").read_text())
        image = yaml.safe_load((ROOT / "container/settings.template.yml").read_text())

        self.assertEqual(
            set(upstream["plugins"]), set(image["plugins"]) - {"searxng_access.plugin.SXNGPlugin"}
        )
        self.assertTrue(image["plugins"]["searxng_access.plugin.SXNGPlugin"]["active"])
        self.assertIn("json", image["search"]["formats"])
