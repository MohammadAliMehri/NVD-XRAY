import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pocindex_client import parse_pocindex_html
from schemas import VulnerabilityReport
from service import hydrate_nvd_evidence, research_report


SAMPLE_HTML = """
<html><body>
<h2>Proof-of-concept exploits (12)</h2>
<ul>
  <li><a href="https://github.com/example/first-poc">example/first-poc</a><span>Repo stars 42★ · pushed 2026-01-10 · <a href="https://web.archive.org/web/*/https://github.com/example/first-poc">find archive</a></span></li>
  <li><a href="https://www.exploit-db.com/exploits/12345">Exploit 12345</a></li>
</ul>
<h2>CVE references</h2>
</body></html>
"""


class PocIndexTests(unittest.TestCase):
    def test_parser_extracts_bounded_public_metadata(self):
        result = parse_pocindex_html(SAMPLE_HTML, limit=1)

        self.assertEqual(result["total_count"], 12)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["name"], "example/first-poc")
        self.assertEqual(result["items"][0]["stars"], 42)
        self.assertEqual(result["items"][0]["pushed_at"], "2026-01-10")
        self.assertEqual(result["items"][0]["source"], "GitHub")

    @patch("service.PocIndexClient")
    @patch("service.research")
    def test_research_report_enriches_exact_cve(self, mock_research, mock_client):
        model_report = VulnerabilityReport(
            cve_id="CVE-2026-1234",
            summary="Verified CVE summary.",
        )
        mock_research.return_value = {"structured_response": model_report}
        mock_client.return_value.get_public_pocs.return_value = {
            "total_count": 2,
            "index_url": "https://pocindex.io/CVE-2026-1234",
            "items": [
                {
                    "name": "example/public-poc",
                    "url": "https://github.com/example/public-poc",
                    "source": "GitHub",
                    "stars": 10,
                    "pushed_at": "2026-01-10",
                }
            ],
        }

        report, _ = research_report("CVE-2026-1234")

        self.assertEqual(report.public_poc_count, 2)
        self.assertEqual(report.public_pocs[0].name, "example/public-poc")
        self.assertEqual(str(report.poc_index_url),
                         "https://pocindex.io/CVE-2026-1234")

    def test_hydrates_deterministic_nvd_metadata(self):
        report = VulnerabilityReport(
            cve_id="CVE-2026-1234",
            summary="Model summary.",
            severity="LOW",
            cvss_score=2.0,
        )
        evidence = {
            "cve_id": "CVE-2026-1234",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published": "2026-01-01",
            "last_modified": "2026-01-05",
            "affected_product_total": 8,
            "reference_total": 3,
            "evidence_truncated": True,
        }
        result = {
            "messages": [
                SimpleNamespace(name="get_cve_details", content=json.dumps(evidence))
            ]
        }

        hydrated = hydrate_nvd_evidence(report, result)

        self.assertEqual(hydrated.severity, "CRITICAL")
        self.assertEqual(hydrated.cvss_score, 9.8)
        self.assertEqual(hydrated.affected_product_total, 8)
        self.assertTrue(any("bounded sample" in item for item in hydrated.limitations))


if __name__ == "__main__":
    unittest.main()
