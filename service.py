import json
import os
import re
from typing import Any

from pydantic import ValidationError

from agent import research
from pocindex_client import PocIndexClient, PocIndexError
from schemas import PublicPoc, VulnerabilityReport


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MAX_QUERY_LENGTH = 300


class ResearchInputError(ValueError):
    pass


def validated_report(result: dict[str, Any]) -> VulnerabilityReport:
    response = result.get("structured_response")
    if isinstance(response, VulnerabilityReport):
        return response
    if isinstance(response, dict):
        return VulnerabilityReport.model_validate(response)
    raise RuntimeError("The agent did not return a structured response.")


def hydrate_nvd_evidence(
    report: VulnerabilityReport, result: dict[str, Any]
) -> VulnerabilityReport:
    for message in result.get("messages", []):
        if getattr(message, "name", None) != "get_cve_details":
            continue
        try:
            evidence = json.loads(str(message.content))
        except (json.JSONDecodeError, TypeError):
            continue
        if evidence.get("found") is False:
            continue

        limitations = list(report.limitations)
        if evidence.get("evidence_truncated"):
            limitations.append(
                "The model received a bounded sample of affected products and references; full totals are shown."
            )
        updates = {
            "cve_id": evidence.get("cve_id") or report.cve_id,
            "severity": evidence.get("severity") or report.severity,
            "cvss_score": evidence.get("cvss_score")
            if evidence.get("cvss_score") is not None
            else report.cvss_score,
            "published": evidence.get("published") or report.published,
            "last_modified": evidence.get("last_modified") or report.last_modified,
            "affected_product_total": evidence.get("affected_product_total", 0)
            or len(report.affected_products),
            "reference_total": evidence.get("reference_total", 0)
            or len(report.references),
            "limitations": list(dict.fromkeys(limitations)),
        }
        return report.model_copy(update=updates)
    return report


def research_report(query: str) -> tuple[VulnerabilityReport, dict[str, Any]]:
    cleaned = query.strip()
    if not cleaned:
        raise ResearchInputError("Enter a CVE ID or vulnerability keyword.")
    if len(cleaned) > MAX_QUERY_LENGTH:
        raise ResearchInputError(
            f"Query is too long; maximum length is {MAX_QUERY_LENGTH} characters.")
    if cleaned.upper().startswith("CVE-") and not CVE_PATTERN.fullmatch(cleaned.upper()):
        raise ResearchInputError(
            "Use a valid CVE identifier, for example CVE-2021-44228.")

    prompt = (
        f"Research exact CVE {cleaned.upper()}."
        if CVE_PATTERN.fullmatch(cleaned.upper())
        else f"Search NVD for: {cleaned}"
    )
    try:
        result = research(prompt)
        report = validated_report(result)
    except ValidationError as exc:
        raise RuntimeError(
            "The model response did not match the vulnerability report schema.") from exc

    report = hydrate_nvd_evidence(report, result)
    if report.cve_id:
        try:
            poc_data = PocIndexClient(
                timeout=float(os.getenv("POCINDEX_TIMEOUT_SECONDS", "15")),
                limit=int(os.getenv("POCINDEX_RESULT_LIMIT", "6")),
            ).get_public_pocs(report.cve_id)
            report = VulnerabilityReport.model_validate(
                {
                    **report.model_dump(),
                    "public_poc_count": poc_data["total_count"],
                    "public_pocs": [
                        PublicPoc.model_validate(item) for item in poc_data["items"]
                    ],
                    "poc_index_url": poc_data["index_url"],
                }
            )
        except (PocIndexError, ValueError):
            limitations = [*report.limitations]
            limitations.append(
                "Public PoC availability could not be retrieved from PoCIndex; retry later."
            )
            report = report.model_copy(update={"limitations": limitations})

    return report, result
