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
fresh installation. The example uses `latest` by default. For predictable production
deployments, create a local `.env` file with `SEARXNG_ACCESS_VERSION=0.1.1`.

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

> [!NOTE]
> Migrating an existing SearXNG installation? The image will not rewrite your mounted
> `settings.yml`. Add `searxng_access.plugin.SXNGPlugin: {active: true}` to its existing
> `plugins:` mapping once, without removing your other plugin entries.

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
| `SEARXNG_ACCESS_SESSION_IDLE` | `28800` | Idle timeout in seconds |
| `SEARXNG_ACCESS_SESSION_LIFETIME` | `604800` | Maximum session lifetime |

## 🛡️ Security at a glance

- Raw tokens and session IDs are never stored—only SHA-256 hashes.
- Browser cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` by default.
- Revoking a token also invalidates browser sessions created from it.
- Usage counters never contain search queries.
- SQLite contains tokens, sessions, quota windows, and aggregate usage.
- Keep `Authorization` and `X-API-Key` values out of proxy and debug logs.
- After deployment, confirm API requests with missing and invalid tokens both return `401`.

## 📦 Container images

Version tags publish tested `linux/amd64` and `linux/arm64` images to:

```text
ghcr.io/dz-mykolas/searxng-access:0.1.1
ghcr.io/dz-mykolas/searxng-access:latest
```

The publish workflow runs unit and SearXNG integration tests, then publishes an SBOM
and provenance attestation. The first GHCR package publication must be made public once
by a maintainer so VPS users can pull it anonymously.

## 📄 License

[GNU AGPL-3.0-or-later](LICENSE)
