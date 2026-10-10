"""The web dashboard: static files served by the API itself, no build step.

The page holds no data of its own. It calls the same /api/v1 endpoints as any other
client, with the API key the user pastes in, so it sees exactly what that key may see.
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse

STATIC_DIR = Path(__file__).resolve().parents[1] / "dashboard"
FILES = {
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "sample-incident.json": "application/json",
}
SECURITY_HEADERS = {
    # Scripts and styles only from this origin; inline style attributes are used for meter widths.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-cache",
}

router = APIRouter(include_in_schema=False)


@router.get("/")
async def root() -> RedirectResponse:
    return RedirectResponse("/dashboard/")


@router.get("/dashboard")
async def dashboard_no_slash() -> RedirectResponse:
    return RedirectResponse("/dashboard/")


@router.get("/dashboard/")
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html; charset=utf-8", headers=SECURITY_HEADERS)


@router.get("/dashboard/{name}")
async def dashboard_asset(name: str) -> FileResponse:
    if name not in FILES:
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(STATIC_DIR / name, media_type=FILES[name], headers=SECURITY_HEADERS)
