import unittest
from unittest.mock import patch

from engine import evaluate_heuristic, investigate, extract_entities


class FallbackResilienceTests(unittest.TestCase):
    def test_heuristic_detects_brand_spoofing_and_suspicious_tld(self):
        msg = "Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login"
        res = evaluate_heuristic(msg)
        self.assertEqual(res["verdict"], "SCAM")
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertTrue(any("sbi" in w.lower() for w in res["why"]))
        self.assertTrue(any("blocked" in w.lower() for w in res["why"]))
        self.assertTrue(res["complaint"])

    def test_heuristic_detects_upi_collect_fraud(self):
        msg = "Hi, I am sending your refund of Rs. 4,999. Please approve the collect request from refund.support8834@okybl and enter your UPI PIN."
        res = evaluate_heuristic(msg)
        self.assertEqual(res["verdict"], "SCAM")
        self.assertGreaterEqual(res["risk_score"], 65)
        self.assertTrue(any("pin" in w.lower() or "collect" in w.lower() for w in res["why"]))
        self.assertTrue(any("refund" in w.lower() for w in res["why"]))

    def test_heuristic_detects_malicious_apk(self):
        msg = "Install government PM-Kisan subsidy app immediately: http://pm-kisan-portal.online/download.apk"
        res = evaluate_heuristic(msg)
        self.assertEqual(res["verdict"], "SCAM")
        self.assertTrue(any("apk" in w.lower() for w in res["why"]))

    def test_heuristic_recognizes_legitimate_bank_alert(self):
        msg = "Dear SBI Customer, your A/C ending with 4821 has been debited by INR 350.00 on 01-Oct-26 via UPI. Ref No 427819382104. If not done by you, visit https://www.sbi.co.in or call 18001234. Never share your OTP, UPI PIN, or CVV."
        res = evaluate_heuristic(msg)
        self.assertEqual(res["verdict"], "SAFE")
        self.assertLess(res["risk_score"], 30)

    def test_investigate_seamlessly_falls_back_when_llm_fails(self):
        with patch("engine.run_gemini_agent", side_effect=RuntimeError("Quota exceeded 429")):
            msg = "URGENT: Electricity disconnected tonight. Pay at http://bijli-bill-update.xyz/pay"
            res = investigate(msg)

            self.assertEqual(res["engine"], "heuristic_fallback")
            self.assertIn("Quota exceeded 429", res.get("fallback_reason", ""))
            self.assertEqual(res["verdict"], "SCAM")
            self.assertGreaterEqual(res["risk_score"], 65)

    def test_invalid_gemini_verdict_falls_back_instead_of_being_safe(self):
        with patch("engine.run_gemini_agent", return_value="The message seems okay, but no verdict was formatted."):
            res = investigate("Your account will be blocked. Verify KYC immediately.")

        self.assertEqual(res["engine"], "heuristic_fallback")
        self.assertEqual(res["verdict"], "SUSPICIOUS")


if __name__ == "__main__":
    unittest.main()
