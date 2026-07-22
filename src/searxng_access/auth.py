"""HTTP access-token parsing."""


def parse_bearer_token(header: str | None) -> str | None:
    """Return a bearer token from an Authorization header, if it is well formed."""

    if header is None:
        return None

    parts = header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    if not token or any(character.isspace() for character in token):
        return None
    return token


def parse_api_key(header: str | None) -> str | None:
    """Return a token from an X-API-Key header, if it is well formed."""

    if header is None:
        return None

    token = header.strip()
    if not token or any(character.isspace() for character in token):
        return None
    return token
