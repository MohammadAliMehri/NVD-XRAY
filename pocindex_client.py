import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

import httpx


POCINDEX_BASE_URL = "https://pocindex.io"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
COUNT_PATTERN = re.compile(r"\((\d[\d,]*)\)")
METADATA_PATTERN = re.compile(
    r"Repo stars\s+(\d[\d,]*)\s*★\s*·\s*pushed\s+(\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)


class PocIndexError(RuntimeError):
    pass


class _PocIndexParser(HTMLParser):
    def __init__(self, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.limit = limit
        self.total_count = 0
        self.items: list[dict[str, Any]] = []
        self._capture_heading = False
        self._heading_parts: list[str] = []
        self._in_poc_section = False
        self._capture_item = False
        self._current_item: dict[str, Any] | None = None
        self._item_parts: list[str] = []
        self._capture_link = False
        self._link_parts: list[str] = []
        self._link_href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "h2":
            self._capture_heading = True
            self._heading_parts = []
        elif tag == "li" and self._in_poc_section and len(self.items) < self.limit:
            self._capture_item = True
            self._current_item = None
            self._item_parts = []
        elif tag == "a" and self._capture_item:
            self._capture_link = True
            self._link_parts = []
            self._link_href = attributes.get("href")

    def handle_endtag(self, tag: str) -> None:
        if tag == "h2" and self._capture_heading:
            heading = " ".join(self._heading_parts).strip()
            is_poc_heading = heading.lower().startswith("proof-of-concept exploits")
            if is_poc_heading:
                match = COUNT_PATTERN.search(heading)
                self.total_count = int(match.group(1).replace(",", "")) if match else 0
                self._in_poc_section = True
            elif self._in_poc_section:
                self._in_poc_section = False
            self._capture_heading = False
        elif tag == "a" and self._capture_link:
            link_text = " ".join(self._link_parts).strip()
            href = self._link_href or ""
            if (
                self._current_item is None
                and href
                and "web.archive.org" not in href
                and not href.startswith("/")
            ):
                self._current_item = {"name": link_text, "url": href}
            self._capture_link = False
        elif tag == "li" and self._capture_item:
            text = " ".join(self._item_parts).strip()
            if self._current_item:
                metadata = METADATA_PATTERN.search(text)
                if metadata:
                    self._current_item["stars"] = int(metadata.group(1).replace(",", ""))
                    self._current_item["pushed_at"] = metadata.group(2)
                else:
                    self._current_item["stars"] = None
                    self._current_item["pushed_at"] = None
                self._current_item["source"] = _source_name(self._current_item["url"])
                self.items.append(self._current_item)
            self._capture_item = False
            self._current_item = None

    def handle_data(self, data: str) -> None:
        value = data.strip()
        if not value:
            return
        if self._capture_heading:
            self._heading_parts.append(value)
        if self._capture_item:
            self._item_parts.append(value)
        if self._capture_link:
            self._link_parts.append(value)


def _source_name(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host in {"github.com", "www.github.com"}:
        return "GitHub"
    if host.endswith("exploit-db.com"):
        return "Exploit-DB"
    if host.endswith("packetstormsecurity.com"):
        return "Packet Storm"
    return host or "Public reference"


def parse_pocindex_html(html: str, limit: int = 6) -> dict[str, Any]:
    parser = _PocIndexParser(limit=max(limit, 0))
    parser.feed(html)
    return {"total_count": parser.total_count, "items": parser.items}


class PocIndexClient:
    def __init__(self, timeout: float = 15.0, limit: int = 6) -> None:
        self.timeout = timeout
        self.limit = max(min(limit, 20), 0)

    def get_public_pocs(self, cve_id: str) -> dict[str, Any]:
        normalized = cve_id.strip().upper()
        if not CVE_PATTERN.fullmatch(normalized):
            raise ValueError("A valid CVE identifier is required for PoCIndex lookup.")

        page_url = f"{POCINDEX_BASE_URL}/{normalized}"
        try:
            response = httpx.get(
                page_url,
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": "NVD-XRAY/1.0 (+https://github.com/MohammadAliMehri/NVD-XRAY)"},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise PocIndexError(f"PoCIndex request failed: {exc}") from exc

        parsed = parse_pocindex_html(response.text, self.limit)
        return {
            "cve_id": normalized,
            "index_url": page_url,
            "total_count": parsed["total_count"],
            "items": parsed["items"],
        }
