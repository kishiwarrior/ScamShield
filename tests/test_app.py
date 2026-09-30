import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app


class ScamShieldToolTests(unittest.TestCase):
    def test_private_ip_is_rejected_without_request(self):
        with patch.object(app.requests, "head") as head:
            result = app.analyze_url("http://127.0.0.1/admin")

        self.assertIn("error", result)
        head.assert_not_called()

    def test_redirect_to_private_ip_is_blocked(self):
        redirect = type("Response", (), {
            "headers": {"Location": "http://169.254.169.254/latest/meta-data"},
            "is_redirect": True,
            "status_code": 302,
        })()
        with patch.object(app.socket, "getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]), \
                patch.object(app.requests, "head", return_value=redirect) as head:
            result = app.analyze_url("https://example.com")

        self.assertIn("error", result)
        self.assertEqual(len(result["redirect_chain"]), 1)
        head.assert_called_once()

    def test_missing_virustotal_key_is_a_graceful_result(self):
        with patch.dict(os.environ, {}, clear=True):
            result = app.check_domain_reputation("example.com")

        self.assertFalse(result["available"])
        self.assertIn("VIRUSTOTAL_API_KEY", result["message"])

    def test_entity_extraction_finds_sample_indicators(self):
        result = app.extract_entities("Account blocked. Update KYC: http://sbi-kyc-update.xyz/login")

        self.assertEqual(result["urls"], ["http://sbi-kyc-update.xyz/login"])
        self.assertIn("blocked", result["urgency_words"])

    def test_gemini_agent_runs_tool_and_sends_result_back(self):
        tool_call = SimpleNamespace(
            type="function_call", name="extract_entities", id="call-1",
            arguments={"text": "sample message"},
            model_dump=Mock(return_value={
                "type": "function_call", "name": "extract_entities", "id": "call-1",
                "arguments": {"text": "sample message"},
            }),
        )
        final_step = Mock(type="model_output")
        final_step.model_dump.return_value = {"type": "model_output", "content": []}
        client = Mock()
        client.interactions.create.side_effect = [
            SimpleNamespace(steps=[tool_call], output_text=""),
            SimpleNamespace(steps=[final_step], output_text="VERDICT: SAFE"),
        ]
        ui = Mock()

        with patch.object(app, "_get_gemini_client", return_value=client), \
                patch.dict(app.TOOL_FUNCS, {"extract_entities": lambda text: {"text": text}}):
            result = app.run_agent("sample message", ui)

        self.assertEqual(result, "VERDICT: SAFE")
        self.assertEqual(client.interactions.create.call_count, 2)
        first_request = client.interactions.create.call_args_list[0].kwargs
        second_request = client.interactions.create.call_args_list[1].kwargs
        self.assertFalse(first_request["store"])
        history_types = [part["type"] for part in second_request["input"]]
        result_index = history_types.index("function_result")
        self.assertEqual(history_types[result_index - 1], "function_call")
        self.assertEqual(second_request["input"][result_index]["call_id"], "call-1")
        ui.json.assert_called_once_with({"text": "sample message"})


if __name__ == "__main__":
    unittest.main()