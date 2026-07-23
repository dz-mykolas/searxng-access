# Repository rules

- Pin external tools and images; pin GitHub Actions to commit SHAs.
- Before release, bump with `uv version`, then verify the version in `README.md`, `compose.example.yaml`, and `examples/caddy/compose.yaml`.
- Before release, run lint, all tests, and the container smoke test.
