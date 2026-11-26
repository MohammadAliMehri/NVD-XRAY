import unittest

from nvd_client import normalize_cve
from schemas import VulnerabilityReport


class NvdClientTests(unittest.TestCase):
    def test_normalize_preserves_unknown_score_and_versions(self):
        result = normalize_cve(
            {
                "cve": {
                    "id": "CVE-2026-1234",
                    "descriptions": [{"lang": "en", "value": "Example description"}],
                    "metrics": {},
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"}],
                }
            }
        )

        self.assertEqual(result["cve_id"], "CVE-2026-1234")
        self.assertIsNone(result["cvss_score"])
        self.assertEqual(result["affected_products"], [])

    def test_report_accepts_keyword_search_shape(self):
        report = VulnerabilityReport.model_validate(
            {
                "summary": "Search completed with one match.",
                "search_results": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "summary": "Apache Log4j vulnerability",
                    }
                ],
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
            }
        )

        self.assertEqual(report.search_results[0].cve_id, "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
