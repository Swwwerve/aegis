"""FIRST's daily probability of exploitation in the next 30 days."""

from datetime import UTC, date, datetime

from ..schemas.vulnerability import EPSSReading
from .feed_client import CVE, FeedClient, FeedError

EPSS_URL = "https://api.first.org/data/v1/epss"


class EPSSClient(FeedClient):
    async def lookup(self, cves: list[str]) -> dict[str, EPSSReading]:
        ids = sorted(set(cves))
        if len(ids) > 10000 or any(not CVE.fullmatch(cve) for cve in ids):
            raise FeedError("Invalid EPSS CVE inventory")
        readings = {}
        # FIRST limits the comma-separated CVE parameter to 2000 characters.
        batches = []
        batch = []
        for cve in ids:
            if batch and (len(",".join([*batch, cve])) > 1900 or len(batch) >= 100):
                batches.append(batch)
                batch = []
            batch.append(cve)
        if batch:
            batches.append(batch)
        for batch in batches:
            offset = 0
            for _ in range(101):
                data = await self.get_json(
                    EPSS_URL, {"cve": ",".join(batch), "limit": 100, "offset": offset}
                )
                try:
                    if data["status"] != "OK" or not isinstance(data["data"], list):
                        raise ValueError()
                    total = data["total"]
                    if type(total) is not int or not 0 <= total <= len(batch):
                        raise ValueError()
                    if data.get("offset", offset) != offset:
                        raise ValueError()
                    for row in data["data"]:
                        if row["cve"] not in batch or row["cve"] in readings:
                            raise ValueError()
                        day = date.fromisoformat(row["date"])
                        if day > datetime.now(UTC).date():
                            raise ValueError()
                        readings[row["cve"]] = EPSSReading(
                            cve=row["cve"],
                            probability=row["epss"],
                            percentile=row["percentile"],
                            date=day.isoformat(),
                        )
                    offset += len(data["data"])
                    if offset == total:
                        break
                    if not data["data"] or offset > total:
                        raise ValueError()
                except (KeyError, ValueError, TypeError) as exc:
                    raise FeedError("Invalid EPSS response") from exc
            else:
                raise FeedError("EPSS pagination limit exceeded")
        return readings
