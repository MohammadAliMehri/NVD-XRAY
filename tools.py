import json

from langchain.tools import tool

from nvd_client import NvdClient


@tool
def get_cve_details(cve_id: str) -> str:
    """Fetch one NVD CVE record by its exact identifier, such as CVE-2021-44228."""
    result = NvdClient().get_cve_details(cve_id.strip())
    return json.dumps(result, ensure_ascii=False) if result else json.dumps({"found": False})


@tool
def search_cves(keyword: str, limit: int = 5) -> str:
    """Search NVD by a product or vulnerability keyword and return a bounded result set."""
    result = NvdClient().search_cves(keyword.strip(), limit)
    return json.dumps({"query": keyword, "results": result}, ensure_ascii=False)
