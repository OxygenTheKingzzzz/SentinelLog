"""ASGI guard: authenticate mutations before parsing files or reaching the database."""

import secrets

from starlette.responses import JSONResponse

from sentinellog.ratelimit import WindowLimiter


class SecurityMiddleware:
    def __init__(self, app, token: str, max_bytes: int):
        self.app = app
        self.token = token
        self.max_bytes = max_bytes
        self.limiter = WindowLimiter()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        method = scope["method"]
        headers = dict(scope["headers"])
        protected = method not in {"GET", "HEAD", "OPTIONS"} or path in {
            "/api/v1/settings",
            "/api/v1/audit",
            "/api/v1/live/status",
            "/api/v1/live/collectors",
        }
        host = (scope.get("client") or ("unknown", 0))[0]

        async def reject(status, detail):
            response = JSONResponse({"detail": detail}, status_code=status)
            await response(scope, receive, send)

        if not self.limiter.allow(host, "requests", 120, 60):
            return await reject(429, "request limit exceeded")
        if protected and method != "OPTIONS":
            supplied = headers.get(b"authorization", b"")
            expected = ("Bearer " + self.token).encode("utf-8")
            if not self.token or not secrets.compare_digest(supplied, expected):
                return await reject(401, "Administrator access required. Sign in in Settings.")
        try:
            size = int(headers.get(b"content-length", b"0"))
            if size < 0:
                raise ValueError
        except ValueError:
            return await reject(400, "invalid content length")
        if size > self.max_bytes:
            return await reject(413, "request is too large")
        # Enforce the bound even for chunked uploads before multipart parsing spools to disk.
        messages = []
        total = 0
        body = bytearray()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    return await reject(413, "request is too large")
                body.extend(message.get("body", b""))
                if not message.get("more_body", False):
                    messages.append({"type": "http.request", "body": bytes(body)})
                    break

        async def replay():
            if messages:
                return messages.pop(0)
            return await receive()

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                ]
            await send(message)

        await self.app(scope, replay, secure_send)
