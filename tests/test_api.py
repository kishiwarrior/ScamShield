import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from api import EntitiesModel, InvestigationRequest, app


class ScamShieldApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["features"]["heuristic_fallback"])

    def test_samples_endpoint(self):
        response = self.client.get("/api/v1/samples")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("samples", data)
        self.assertGreaterEqual(len(data["samples"]), 3)

    def test_investigate_with_text_field(self):
        payload = {
            "text": "Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login",
            "force_heuristic": True
        }
        response = self.client.post("/api/v1/investigate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["verdict"], "SCAM")
        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn("sbi-kyc-update.xyz", str(data["why"]))

    def test_investigate_alias_with_message_field(self):
        payload = {
            "message": "Hi, I am sending refund. Please approve collect request from refund.support@okybl and enter UPI PIN.",
            "force_heuristic": True
        }
        response = self.client.post("/investigate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["verdict"], "SCAM")

    def test_investigate_validation_error_on_empty_request(self):
        response = self.client.post("/api/v1/investigate", json={"text": "   "})
        self.assertEqual(response.status_code, 422)

    def test_blank_text_falls_back_to_message(self):
        request = InvestigationRequest(text="   ", message="Suspicious message")

        self.assertEqual(request.text, "Suspicious message")

    def test_entity_lists_are_independent(self):
        first = EntitiesModel()
        second = EntitiesModel()
        first.urls.append("https://example.com")

        self.assertEqual(second.urls, [])

    def test_internal_exception_detail_is_not_returned(self):
        with patch("api.investigate", side_effect=RuntimeError("internal service detail")):
            response = self.client.post("/api/v1/investigate", json={"text": "example", "force_heuristic": True})

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"], "Investigation failed. Please retry.")


if __name__ == "__main__":
    unittest.main()
