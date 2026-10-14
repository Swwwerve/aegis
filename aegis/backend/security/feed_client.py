"""Bounded, retrying transport for fixed public advisory endpoints."""

import asyncio
import re

import httpx

CVE = re.compile(r"CVE-\d{4}-\d{4,}")


class FeedError(ValueError):
    pass


class FeedClient:
    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self.http = http_client or httpx.AsyncClient(
            timeout=20, follow_redirects=False, trust_env=False
        )
        self.owned = http_client is None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        if self.owned:
            await self.http.aclose()

    async def get_json(self, url: str, params: dict | None = None):
        for attempt in range(3):
            try:
                async with self.http.stream("GET", url, params=params) as response:
                    if (
                        response.status_code == 429 or response.status_code >= 500
                    ) and attempt < 2:
                        await asyncio.sleep(0.1 * 2**attempt)
                        continue
                    response.raise_for_status()
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > 8 * 1024 * 1024:
                            raise FeedError("Feed exceeds response size limit")
                    import json

                    return json.loads(content)
            except httpx.TransportError:
                if attempt < 2:
                    await asyncio.sleep(0.1 * 2**attempt)
                    continue
                raise FeedError("Feed transport unavailable") from None
            except (httpx.HTTPStatusError, ValueError) as exc:
                if isinstance(exc, FeedError):
                    raise
                raise FeedError("Feed returned invalid data or HTTP error") from None
        raise FeedError("Feed unavailable")
