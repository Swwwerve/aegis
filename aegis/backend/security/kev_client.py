"""Fetch the CISA catalog once per assessment, with its official mirror fallback."""

from datetime import UTC, date, datetime

from .feed_client import CVE, FeedClient, FeedError

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


class KEVClient(FeedClient):
    async def catalog(self) -> tuple[dict[str, dict], dict[str, str]]:
        for url in (KEV_URL, KEV_MIRROR):
            try:
                data = await self.get_json(url)
                rows = data["vulnerabilities"]
                if (
                    not isinstance(rows, list)
                    or not rows
                    or type(data["count"]) is not int
                    or data["count"] != len(rows)
                    or len(rows) > 20000
                ):
                    raise ValueError()
                released = datetime.fromisoformat(data["dateReleased"])
                today = datetime.now(UTC).date()
                if released.tzinfo is None or released.date() > today:
                    raise ValueError()
                entries = {}
                for row in rows:
                    cve = row["cveID"]
                    if (
                        not isinstance(cve, str)
                        or not CVE.fullmatch(cve)
                        or cve in entries
                    ):
                        raise ValueError()
                    if date.fromisoformat(row["dateAdded"]) > today:
                        raise ValueError()
                    date.fromisoformat(row["dueDate"])
                    if not isinstance(row.get("requiredAction"), str):
                        raise TypeError()
                    entries[cve] = {**row, "source": url}
                return entries, {
                    "kev_source": url,
                    "kev_catalog_version": str(data["catalogVersion"]),
                    "kev_catalog_released": released.isoformat(),
                    "kev_catalog_stale": str(
                        (today - released.date()).days > 14
                    ).lower(),
                }
            except (FeedError, ValueError, KeyError, TypeError, AttributeError):
                continue
        raise FeedError("CISA KEV catalog and official mirror unavailable or invalid")
