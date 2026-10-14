"""Live OSV API client: batched version queries, per-query pagination and hydration.

Only package identifiers/versions leave the host. No repository code is executed
here, and advisory-provided URLs are never followed.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field

import httpx

from ..core.progress import Progress, emit
from ..schemas.vulnerability import ScanDependency

BASE_URL = "https://api.osv.dev/v1"


class OSVError(RuntimeError):
    """Bounded, credential-free provider failure suitable for a scan report."""


@dataclass
class OSVResult:
    records: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.errors


class OSVClient:
    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        *,
        batch_size: int = 100,
        concurrency: int = 8,
        retries: int = 2,
        backoff: float = 0.25,
        max_pages: int = 100,
        max_records: int = 10000,
        max_response_bytes: int = 8 * 1024 * 1024,
    ):
        if (
            not 1 <= batch_size <= 1000
            or concurrency < 1
            or retries < 0
            or max_pages < 1
            or max_records < 1
            or max_response_bytes < 1
        ):
            raise ValueError("Invalid OSV client limits")
        self.client = client or httpx.AsyncClient(
            timeout=30, follow_redirects=False, trust_env=False
        )
        self._owned = client is None
        self.batch_size, self.retries, self.backoff = batch_size, retries, backoff
        self.max_pages, self.max_records = max_pages, max_records
        self.max_response_bytes = max_response_bytes
        self._requests = asyncio.Semaphore(concurrency)
        self._response_bytes = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        if self._owned:
            await self.client.aclose()

    async def _request(self, method: str, path: str, payload=None) -> dict:
        if self._response_bytes >= 64 * 1024 * 1024:
            raise OSVError("OSV total response budget exceeded")
        for attempt in range(self.retries + 1):
            retry_after = None
            try:
                async with (
                    self._requests,
                    self.client.stream(
                        method, BASE_URL + path, json=payload
                    ) as response,
                ):
                    if response.status_code == 429 or response.status_code >= 500:
                        try:
                            retry_after = min(
                                5.0,
                                max(
                                    0.0, float(response.headers.get("Retry-After", "0"))
                                ),
                            )
                        except ValueError:
                            pass
                        raise OSVError(f"OSV temporary HTTP {response.status_code}")
                    if response.status_code != 200:
                        raise OSVError(f"OSV HTTP {response.status_code}")
                    content = bytearray()
                    async for block in response.aiter_bytes():
                        self._response_bytes += len(block)
                        if self._response_bytes > 64 * 1024 * 1024:
                            raise OSVError("OSV total response budget exceeded")
                        content.extend(block)
                        if len(content) > self.max_response_bytes:
                            raise OSVError("OSV response exceeded size limit")
                    data = json.loads(content)
                    if not isinstance(data, dict):
                        raise OSVError("OSV response is not an object")
                    return data
            except (httpx.TransportError, OSVError) as exc:
                transient = isinstance(
                    exc, httpx.TransportError
                ) or "temporary HTTP" in str(exc)
                if not transient or attempt == self.retries:
                    raise OSVError(
                        str(exc)
                        if isinstance(exc, OSVError)
                        else f"OSV transport failure ({type(exc).__name__})"
                    ) from exc
                await asyncio.sleep(
                    retry_after
                    if retry_after is not None
                    else self.backoff * 2**attempt
                )
            except (ValueError, UnicodeError) as exc:
                raise OSVError("OSV returned invalid JSON") from exc
        raise OSVError("OSV retry limit reached")

    @staticmethod
    def _id(value) -> str:
        if (
            not isinstance(value, str)
            or len(value) > 200
            or not re.fullmatch(r"[A-Za-z0-9:_.-]+", value)
        ):
            raise OSVError("OSV returned an invalid advisory ID")
        return value

    @staticmethod
    def _query(dependency):
        return {
            "package": {"name": dependency.package, "ecosystem": dependency.ecosystem},
            "version": dependency.installed_version,
        }

    async def query_packages(
        self, dependencies: list[ScanDependency], *, progress: Progress | None = None
    ) -> list[OSVResult]:
        if len(dependencies) > 10000:
            raise OSVError("OSV query count exceeds 10000-package limit")
        results = [OSVResult() for _ in dependencies]
        ids: list[set[str]] = [set() for _ in dependencies]
        all_ids: set[str] = set()
        completed = 0

        async def query_batch(start):
            nonlocal completed
            pending = [
                (index, self._query(dependencies[index]))
                for index in range(
                    start, min(start + self.batch_size, len(dependencies))
                )
            ]
            tokens: dict[int, set[str]] = {index: set() for index, _ in pending}
            for _ in range(self.max_pages):
                try:
                    data = await self._request(
                        "POST",
                        "/querybatch",
                        {"queries": [query for _, query in pending]},
                    )
                    rows = data.get("results")
                    if not isinstance(rows, list) or len(rows) != len(pending):
                        raise OSVError(
                            "OSV batch result count does not match query count"
                        )
                except OSVError as exc:
                    for index, _ in pending:
                        results[index].errors.append(str(exc))
                    break
                following = []
                for (index, query), row in zip(pending, rows, strict=True):
                    try:
                        if not isinstance(row, dict) or (
                            "vulns" in row and not isinstance(row["vulns"], list)
                        ):
                            raise OSVError("Malformed OSV batch result")
                        if row.get("error"):
                            raise OSVError("OSV rejected package query")
                        for item in row.get("vulns", []):
                            identifier = self._id(
                                item.get("id") if isinstance(item, dict) else None
                            )
                            if (
                                identifier not in all_ids
                                and len(all_ids) >= self.max_records
                            ):
                                raise OSVError("OSV advisory count limit reached")
                            all_ids.add(identifier)
                            ids[index].add(identifier)
                        token = row.get("next_page_token")
                        if token:
                            if not isinstance(token, str) or token in tokens[index]:
                                raise OSVError(
                                    "OSV pagination token repeated or malformed"
                                )
                            tokens[index].add(token)
                            following.append((index, query | {"page_token": token}))
                    except OSVError as exc:
                        results[index].errors.append(str(exc))
                pending = following
                if not pending:
                    break
            else:
                for index, _ in pending:
                    results[index].errors.append("OSV pagination limit reached")
            completed += min(self.batch_size, len(dependencies) - start)
            await emit(
                progress,
                "advisories",
                "running",
                f"Queried {completed}/{len(dependencies)} package versions; found {len(all_ids)} unique advisory records.",
                packages_queried=completed,
                packages_total=len(dependencies),
            )

        await asyncio.gather(
            *(
                query_batch(start)
                for start in range(0, len(dependencies), self.batch_size)
            )
        )
        unique = sorted(all_ids)
        if len(unique) > self.max_records:
            unique = unique[: self.max_records]

        await emit(
            progress,
            "advisories",
            "running",
            f"Downloading {len(unique)} unique advisory records for validation.",
            advisories_completed=0,
            advisories_total=len(unique),
        )
        hydrated_count = 0

        async def hydrate(identifier):
            nonlocal hydrated_count
            error = None
            try:
                record = await self._request("GET", "/vulns/" + identifier)
                if record.get("id") != identifier:
                    raise OSVError("OSV advisory ID mismatch")
            except OSVError as exc:
                record, error = None, str(exc)
            hydrated_count += 1
            if hydrated_count % 20 == 0 or hydrated_count == len(unique):
                await emit(
                    progress,
                    "advisories",
                    "running",
                    f"Downloaded {hydrated_count}/{len(unique)} advisory records (including failed requests).",
                    advisories_completed=hydrated_count,
                    advisories_total=len(unique),
                )
            return identifier, record, error

        hydrated = {
            identifier: (record, error)
            for identifier, record, error in await asyncio.gather(
                *(hydrate(identifier) for identifier in unique)
            )
        }
        for index, identifiers in enumerate(ids):
            for identifier in sorted(identifiers):
                record, error = hydrated.get(
                    identifier, (None, "OSV advisory count limit reached")
                )
                if error:
                    results[index].errors.append(f"{identifier}: {error}")
                else:
                    results[index].records.append(record)
        return results
