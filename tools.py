import json
import os
from typing import Any

from langchain.tools import tool

from nvd_client import NvdClient


def compact_for_model(record: dict[str, Any]) -> dict[str, Any]:
    product_limit = max(int(os.getenv("NVD_MODEL_PRODUCT_LIMIT", "20")), 1)
    reference_limit = max(int(os.getenv("NVD_MODEL_REFERENCE_LIMIT", "12")), 1)
    products = record.get("affected_products", [])
    references = list(record.get("references", []))
    tag_priority = {
        "Vendor Advisory": 0,
        "Patch": 1,
        "Mitigation": 2,
        "Third Party Advisory": 3,
        "Release Notes": 4,
    }
    references.sort(
        key=lambda item: min(
            (tag_priority.get(tag, 9) for tag in item.get("tags", [])),
            default=9,
        )
    )
    references = list({item["url"]: item for item in references}.values())
    compacted = dict(record)
    compacted["affected_products"] = products[:product_limit]
    compacted["references"] = references[:reference_limit]
    compacted["affected_product_total"] = len(products)
    compacted["reference_total"] = len(references)
    compacted["evidence_truncated"] = (
        len(products) > product_limit or len(references) > reference_limit
    )
    return compacted


@tool
def get_cve_details(cve_id: str) -> str:
    """Fetch one NVD CVE record by its exact identifier, such as CVE-2021-44228."""
    result = NvdClient().get_cve_details(cve_id.strip())
    if not result:
        return json.dumps({"found": False})
    return json.dumps(compact_for_model(result), ensure_ascii=False)


@tool
def search_cves(keyword: str, limit: int = 5) -> str:
    """Search NVD by a product or vulnerability keyword and return a bounded result set."""
    result = NvdClient().search_cves(keyword.strip(), limit)
    compacted = [compact_for_model(record) for record in result[:5]]
    return json.dumps({"query": keyword, "results": compacted}, ensure_ascii=False)
