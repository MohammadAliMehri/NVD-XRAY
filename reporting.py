from collections import defaultdict
from textwrap import fill, indent

from schemas import AffectedProduct, VulnerabilityReport


SEVERITY_LABELS = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def _heading(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def _wrapped(text: str, width: int = 96) -> str:
    return fill(text, width=width, subsequent_indent="  ")


def compact_products(products: list[AffectedProduct]) -> list[AffectedProduct]:
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for item in products:
        key = (item.vendor, item.product)
        for version in item.affected_versions or ["Version applicability not provided"]:
            if version not in grouped[key]:
                grouped[key].append(version)
    return [
        AffectedProduct(vendor=vendor, product=product,
                        affected_versions=versions)
        for (vendor, product), versions in grouped.items()
    ]


def format_report(report: VulnerabilityReport) -> str:
    severity = SEVERITY_LABELS.get(
        (report.severity or "UNKNOWN").upper(), "UNKNOWN")
    score = f"{report.cvss_score:.1f}" if report.cvss_score is not None else "Unknown"
    title = report.cve_id or "NVD Keyword Research"
    lines = [
        "NVD-XRAY Vulnerability Brief",
        "=" * 28,
        f"Target: {title}",
        f"Severity: {severity}  |  CVSS: {score}  |  Confidence: {report.confidence.upper()}",
        f"Published: {report.published or 'Unknown'}  |  Updated: {report.last_modified or 'Unknown'}",
        f"Evidence source: {report.data_source}",
        _heading("Executive Summary"),
        _wrapped(report.summary),
        _heading("Impact & Exposure"),
        _wrapped(report.impact or "Impact analysis was not available in the report."),
        _wrapped(
            report.attack_surface or "Attack-surface details were not available in the report."),
    ]

    products = compact_products(report.affected_products)
    lines.append(_heading("Affected Products"))
    if products:
        total = report.affected_product_total or len(report.affected_products)
        lines.append(
            f"- Source records: {total}; model sample: {len(report.affected_products)}")
        for item in products[:20]:
            versions = ", ".join(
                item.affected_versions) or "Version applicability unknown"
            lines.append(f"- {item.vendor} / {item.product}: {versions}")
        if len(products) > 20:
            lines.append(
                f"- ... and {len(products) - 20} additional product entries")
    else:
        lines.append(
            "- Affected product or version data is not available in the NVD result.")

    if report.search_results:
        lines.append(_heading("Matching CVEs"))
        for match in report.search_results:
            score_text = f" / CVSS {match.cvss_score:g}" if match.cvss_score is not None else ""
            lines.append(
                f"- {match.cve_id} [{match.severity or 'UNKNOWN'}{score_text}]")
            lines.append(indent(_wrapped(match.summary), "  "))

    lines.append(_heading("Remediation"))
    remediation = report.remediation or [
        "No NVD-confirmed remediation was supplied."]
    lines.extend(f"- {_wrapped(item)}" for item in remediation)

    lines.append(_heading("Security Recommendations"))
    recommendations = report.security_recommendations or [
        "No additional defensive guidance was supplied."]
    lines.extend(f"- {_wrapped(item)}" for item in recommendations)

    lines.append(_heading("Limitations"))
    limitations = report.limitations or [
        "No report limitations were identified."]
    lines.extend(f"- {_wrapped(item)}" for item in limitations)

    lines.append(_heading("Public PoCs"))
    if report.public_pocs:
        lines.append(f"- PoCIndex matches: {report.public_poc_count}")
        for poc in report.public_pocs:
            metadata = []
            if poc.stars is not None:
                metadata.append(f"{poc.stars} stars")
            if poc.pushed_at:
                metadata.append(f"pushed {poc.pushed_at}")
            suffix = f" ({', '.join(metadata)})" if metadata else ""
            lines.append(f"- {poc.source}: {poc.name}{suffix}")
            lines.append(f"  {poc.url}")
        if report.poc_index_url:
            lines.append(f"- Full PoCIndex listing: {report.poc_index_url}")
        lines.append(
            "- Links are indexed metadata only; NVD-XRAY does not download or execute PoC code.")
    else:
        lines.append("- No public PoC metadata was available for this CVE.")

    lines.append(_heading("References"))
    if report.reference_total:
        lines.append(
            f"- Source references: {report.reference_total}; report sample: {len(report.references)}")
    if report.references:
        lines.extend(f"- {reference.url}" for reference in report.references)
    else:
        lines.append("- No references were supplied.")

    return "\n".join(lines)
