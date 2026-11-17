"""
Request-body size limit enforced while the body is being received.

The upload route rejects oversized *declared* bodies via Content-Length before parsing, but a
client can omit Content-Length (chunked transfer encoding). Starlette's multipart parser spools
file parts to disk before the route's streaming size check runs, and its `max_part_size` applies
only to non-file fields. This pure-ASGI middleware therefore counts the bytes actually received
for the configured path and aborts as soon as the limit is exceeded, so an unbounded chunked
upload can never be spooled to disk regardless of the reverse proxy in front of the API.
"""
from typing import Callable


class RequestBodyTooLarge(Exception):
    """Raised from inside `receive()` when the request body exceeds the configured limit."""


class BodySizeLimitMiddleware:
    def __init__(self, app, path: str, limit_bytes: Callable[[], int]):
        self.app = app
        self.path = path
        self.limit_bytes = limit_bytes  # callable so tests / settings changes take effect

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") != self.path:
            await self.app(scope, receive, send)
            return

        limit = int(self.limit_bytes())
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise RequestBodyTooLarge()
            return message

        await self.app(scope, limited_receive, send)
