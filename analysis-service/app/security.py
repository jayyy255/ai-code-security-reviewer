import hmac
import os

from fastapi import Header, HTTPException


def require_gateway(x_analysis_token: str | None = Header(default=None)):
    """Only the authenticated gateway may submit analysis jobs."""
    expected = os.environ.get("ANALYSIS_SERVICE_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(503, "Analysis service authentication is not configured.")
    if not x_analysis_token or not hmac.compare_digest(x_analysis_token.encode(), expected.encode()):
        raise HTTPException(401, "Authenticated gateway access required.")
