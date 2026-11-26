import unittest
from unittest.mock import patch

from app import create_app
from schemas import VulnerabilityReport


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_health_and_home_page(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'research-form', response.data)

    def test_empty_query_is_rejected(self):
        response = self.client.post("/api/research", json={"query": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Enter a CVE ID", response.get_json()["error"])

    @patch("app.research_report")
    def test_backend_details_are_not_exposed(self, mock_research):
        mock_research.side_effect = RuntimeError("secret-provider-detail")

        with self.assertLogs("app", level="ERROR"):
            response = self.client.post(
                "/api/research", json={"query": "CVE-2026-1234"})

        self.assertEqual(response.status_code, 502)
        self.assertNotIn("secret-provider-detail",
                         response.get_json()["error"])

    @patch("app.research_report")
    def test_research_returns_compacted_report(self, mock_research):
        report = VulnerabilityReport(
            cve_id="CVE-2026-1234",
            summary="Verified report summary.",
            affected_products=[
                {"vendor": "example", "product": "server",
                    "affected_versions": ["1.0"]},
                {"vendor": "example", "product": "server",
                    "affected_versions": ["1.1"]},
            ],
        )
        mock_research.return_value = (report, {})

        response = self.client.post(
            "/api/research", json={"query": "CVE-2026-1234"})

        self.assertEqual(response.status_code, 200)
        products = response.get_json()["report"]["affected_products"]
        self.assertEqual(len(products), 1)
        self.assertEqual(products[0]["affected_versions"], ["1.0", "1.1"])


if __name__ == "__main__":
    unittest.main()
