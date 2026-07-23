# 🔐 SearXNG Access

Token-based access control plugin for [SearXNG](https://github.com/searxng/searxng)
with API tokens, capabilities, quotas, browser sessions, and revocation.

## 🚀 Quick start

### 1. Start it

```bash
mkdir searxng-access && cd searxng-access

curl -fsSL \
  https://raw.githubusercontent.com/dz-mykolas/searxng-access/main/compose.example.yaml \
  -o compose.yaml

mkdir core-config
docker compose up -d
```

The image already contains SearXNG and enables the access plugin automatically on a
fresh installation. The example is pinned to version `0.1.3`.

> [!IMPORTANT]
> Browser login requires HTTPS in production. For temporary local HTTP testing, set
> `SEARXNG_ACCESS_SECURE_COOKIE=false` on the `core` service.

### 2. Create a browser token

```bash
docker compose exec core searxng-access token create \
  --label browser --capability search --capability access
```

> `--label` is only a human-readable name for identifying the token later.

Open your SearXNG URL and paste the generated token. It is shown only once.
The browser stays signed in for up to 30 days, or until it is inactive for 7 days.

### 3. Create an API token

```bash
docker compose exec core searxng-access token create \
  --label ai-harness --capability search --limit 1000 --window 3600
```

```bash
curl \
  -H 'Authorization: Bearer sxng_REPLACE_ME' \
  'https://search.example.com/search?q=searxng&format=json'
```

> [!TIP]
> `X-API-Key: sxng_REPLACE_ME` is also accepted for clients such as LibreChat.

Limited tokens return `429 Too Many Requests` with a standard `Retry-After` header
when their current quota window is exhausted.

> [!NOTE]
> Migrating an existing SearXNG installation? The image will not rewrite your mounted
> `settings.yml`. Add `searxng_access.plugin.SXNGPlugin: {active: true}` to its existing
> `plugins:` mapping once, without removing your other plugin entries.

## 🌐 VPS with automatic HTTPS

For a public VPS, use the Caddy example instead of the basic Compose file. Point your
domain to the server and allow inbound ports `80` and `443`, then run:

```bash
mkdir searxng-access && cd searxng-access

curl -fsSL \
  https://raw.githubusercontent.com/dz-mykolas/searxng-access/main/examples/caddy/compose.yaml \
  -o compose.yaml
curl -fsSL \
  https://raw.githubusercontent.com/dz-mykolas/searxng-access/main/examples/caddy/Caddyfile \
  -o Caddyfile

printf '%s\n' \
  'SEARXNG_HOST=search.example.com' \
  'SEARXNG_ACCESS_VERSION=0.1.3' > .env

mkdir core-config
docker compose up -d
```

Caddy obtains and renews the HTTPS certificate automatically. Only Caddy exposes host
ports; SearXNG remains reachable solely inside the Compose network.

## 🛠️ Development

Open the repository in its devcontainer, or use Debian with Python 3.11, `uv`, build
tools, and the native libraries from the included Dockerfile.

```bash
make setup
make lint test test-integration
make run
```

Then open <http://localhost:8888/> and use:

```text
development-token
```

API example:

```bash
curl \
  -H 'Authorization: Bearer development-token' \
  http://localhost:8888/config
```

| Path | Used for |
| --- | --- |
| `.venv/` | Plugin tooling and unit tests |
| `.searxng/local/py3/` | Pinned SearXNG and integration tests |

## 🔑 Capabilities

| Capability | Access |
| --- | --- |
| `search` | Search, autocomplete, images, and favicons |
| `access` | Preferences, information, and browser account routes |
| `admin` | Metrics and detailed engine errors |
| `*` | Every classified capability |

Browser tokens normally need `search` + `access`. Search-only API clients need
`search`. Unknown routes fail closed until explicitly classified.

## 🎛️ Token management

```bash
# List tokens
docker compose exec core searxng-access token list

# Revoke a token and its browser sessions
docker compose exec core searxng-access token revoke TOKEN_ID

# View aggregate usage counters
docker compose exec core searxng-access usage
```

## ⚙️ Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEARXNG_ACCESS_DB` | `/var/cache/searxng/access.db` in the image | Database path |
| `SEARXNG_ACCESS_SECURE_COOKIE` | `true` | HTTPS-only browser cookies |
| `SEARXNG_ACCESS_SESSION_IDLE` | `604800` | Idle timeout in seconds |
| `SEARXNG_ACCESS_SESSION_LIFETIME` | `2592000` | Maximum session lifetime |

## 🛡️ Security at a glance

- Raw tokens and session IDs are never stored—only SHA-256 hashes.
- Browser cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` by default.
- Browser sessions persist across restarts until their idle or absolute timeout.
- Revoking a token also invalidates browser sessions created from it.
- Usage counters never contain search queries.
- SQLite contains tokens, sessions, quota windows, and aggregate usage.
- Keep `Authorization` and `X-API-Key` values out of proxy and debug logs.
- After deployment, confirm API requests with missing and invalid tokens both return `401`.

## 📦 Container images

Version tags publish tested `linux/amd64` and `linux/arm64` images to:

```text
ghcr.io/dz-mykolas/searxng-access:0.1.3
```

The publish workflow runs unit and SearXNG integration tests, then publishes an SBOM
and provenance attestation. The first GHCR package publication must be made public once
by a maintainer so VPS users can pull it anonymously.

## 🗺️ Roadmap

### ✅ Done

- [x] Bearer token and `X-API-Key` authentication
- [x] Capabilities, quotas, expiration, and revocation
- [x] Persistent browser sessions with idle and absolute timeouts
- [x] SQLite-backed token, session, quota, and usage storage
- [x] Baked multi-architecture container image
- [x] Caddy deployment example with automatic HTTPS

### 🔜 Planned

- [ ] Automated pull requests for dependency, container image, and GitHub Actions updates

## 📄 License

[GNU AGPL-3.0-or-later](LICENSE)
