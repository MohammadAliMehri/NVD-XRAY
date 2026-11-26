import unittest

from reporting import compact_products, format_report
from schemas import VulnerabilityReport


class ReportingTests(unittest.TestCase):
    def test_compact_products_merges_duplicate_versions(self):
        report = VulnerabilityReport(
            summary="A verified example vulnerability.",
            affected_products=[
                {"vendor": "apache", "product": "log4j",
                    "affected_versions": ["2.14"]},
                {"vendor": "apache", "product": "log4j",
                    "affected_versions": ["2.15"]},
            ],
        )
        products = compact_products(report.affected_products)

        self.assertEqual(len(products), 1)
        self.assertEqual(products[0].affected_versions, ["2.14", "2.15"])

    def test_format_report_contains_readable_sections(self):
        report = VulnerabilityReport(
            cve_id="CVE-2026-1234",
            summary="A verified example vulnerability.",
            severity="HIGH",
            cvss_score=8.1,
            limitations=["Version ranges were not supplied."],
        )

        output = format_report(report)

        self.assertIn("NVD-XRAY Vulnerability Brief", output)
        self.assertIn("Executive Summary", output)
        self.assertIn("CVSS: 8.1", output)
        self.assertIn("Version ranges were not supplied.", output)


if __name__ == "__main__":
    unittest.main()
