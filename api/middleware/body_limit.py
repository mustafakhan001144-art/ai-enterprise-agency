"""Reject oversized request bodies before they are read into memory."""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

BODY_METHODS = {"POST", "PUT", "PATCH"}


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in BODY_METHODS:
            length = request.headers.get("content-length")
            if length is None:
                return JSONResponse({"detail": "Content-Length required"}, status_code=411)
            if not length.isdigit() or int(length) > self.max_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)
