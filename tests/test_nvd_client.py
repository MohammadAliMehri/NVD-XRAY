import unittest
from unittest.mock import patch

from nvd_client import normalize_cve
from schemas import VulnerabilityReport
from tools import compact_for_model


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

    @patch.dict(
        "os.environ",
        {"NVD_MODEL_PRODUCT_LIMIT": "2", "NVD_MODEL_REFERENCE_LIMIT": "2"},
    )
    def test_compact_for_model_prioritizes_unique_vendor_references(self):
        record = {
            "affected_products": [{"vendor": "v", "product": str(i)} for i in range(3)],
            "references": [
                {"url": "https://example.com/general", "tags": ["Release Notes"]},
                {"url": "https://example.com/vendor", "tags": ["Vendor Advisory"]},
                {"url": "https://example.com/vendor", "tags": ["Vendor Advisory"]},
                {"url": "https://example.com/patch", "tags": ["Patch"]},
            ],
        }

        compacted = compact_for_model(record)
        urls = [reference["url"] for reference in compacted["references"]]

        self.assertEqual(len(compacted["affected_products"]), 2)
        self.assertEqual(urls, ["https://example.com/vendor", "https://example.com/patch"])
        self.assertTrue(compacted["evidence_truncated"])


if __name__ == "__main__":
    unittest.main()
