"""Bearer-token auth for the HTTP/SSE transports.

Only relevant for remote deployment (`--transport http|sse|streamable-http`).
Local stdio clients (Claude Desktop, Claude Code, Cursor) never touch this —
stdio is process-local by construction and needs no additional gate.

The token verified here (`MCP_AUTH_TOKEN`) is this server's own access
secret. It is unrelated to `INTERVALS_ICU_API_KEY`, which authenticates this
server to the Intervals.icu API. Neither is ever logged.
"""

import hmac
import os

from mcp.server.auth.provider import AccessToken

from fastmcp.server.auth.auth import TokenVerifier

_STATIC_ACCESS_TOKEN = AccessToken(
    token="static-bearer-token",  # noqa: S106 - placeholder, not the real secret
    client_id="mcp-auth-token",
    scopes=[],
)


class StaticBearerTokenVerifier(TokenVerifier):
    """Accepts exactly one pre-shared token, constant-time compared.

    Deliberately not an OAuth flow: this wrapper has one caller (the
    connector config on claude.ai) holding one long-lived token, so a
    full OAuth dance would add moving parts without adding security.
    """

    def __init__(self, token: str) -> None:
        super().__init__()
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token, self._token):
            return _STATIC_ACCESS_TOKEN
        return None


def load_http_auth() -> StaticBearerTokenVerifier | None:
    """Build the bearer-token verifier from MCP_AUTH_TOKEN.

    Returns None when the env var is unset or blank — callers must treat
    that as "refuse to bind a network-facing transport", not "run open".
    """
    token = os.environ.get("MCP_AUTH_TOKEN", "").strip()
    if not token:
        return None
    return StaticBearerTokenVerifier(token)
