import os
import time
from typing import Any

import httpx


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClientError(RuntimeError):
    pass


def normalize_cve(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve", {})
    descriptions = cve.get("descriptions", [])
    summary = next(
        (entry.get("value")
         for entry in descriptions if entry.get("lang") == "en"),
        "Unknown",
    )

    severity = None
    cvss_score = None
    for metric_family in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_family, [])
        if metrics:
            cvss_data = metrics[0].get("cvssData", {})
            severity = metrics[0].get(
                "baseSeverity") or cvss_data.get("baseSeverity")
            cvss_score = cvss_data.get("baseScore")
            break

    affected_products: list[dict[str, Any]] = []
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                vendor = parts[3] if len(parts) > 3 else "unknown"
                product = parts[4] if len(parts) > 4 else "unknown"
                version = parts[5] if len(parts) > 5 and parts[5] not in {
                    "*", "-"} else None
                ranges = [
                    value
                    for key, value in match.items()
                    if key.startswith("version") and value
                ]
                if version:
                    ranges.append(version)
                affected_products.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "affected_versions": list(dict.fromkeys(ranges)),
                    }
                )

    references = [
        {
            "url": reference.get("url", ""),
            "source": reference.get("source"),
            "tags": reference.get("tags", []),
        }
        for reference in cve.get("references", [])
        if reference.get("url")
    ]

    return {
        "cve_id": cve.get("id", "Unknown"),
        "summary": summary,
        "severity": severity,
        "cvss_score": cvss_score,
        "affected_products": affected_products,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": references,
        "data_source": "NVD",
    }


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 20.0,
        max_retries: int = 2,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout
        self.max_retries = max_retries

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout, headers=headers) as client:
                    response = client.get(NVD_API_URL, params=params)
                if response.status_code == 200:
                    return response.json()
                if response.status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                    retry_after = response.headers.get("Retry-After")
                    try:
                        delay = min(max(float(retry_after), 0.0),
                                    8.0) if retry_after else 2**attempt
                    except ValueError:
                        delay = 2**attempt
                    time.sleep(delay)
                    continue
                raise NvdClientError(
                    f"NVD request failed with HTTP {response.status_code}: {response.text[:300]}"
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                if attempt < self.max_retries:
                    time.sleep(2**attempt)
                    continue
                break
            except (httpx.HTTPError, ValueError) as exc:
                raise NvdClientError(f"Invalid NVD response: {exc}") from exc

        raise NvdClientError(f"NVD request failed after retries: {last_error}")

    def get_cve_details(self, cve_id: str) -> dict[str, Any] | None:
        payload = self._get({"cveId": cve_id})
        vulnerabilities = payload.get("vulnerabilities", [])
        return normalize_cve(vulnerabilities[0]) if vulnerabilities else None

    def search_cves(self, keyword: str, limit: int = 5) -> list[dict[str, Any]]:
        bounded_limit = min(max(limit, 1), 20)
        payload = self._get(
            {"keywordSearch": keyword, "resultsPerPage": bounded_limit})
        return [normalize_cve(item) for item in payload.get("vulnerabilities", [])]
