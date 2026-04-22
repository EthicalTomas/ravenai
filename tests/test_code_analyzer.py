from __future__ import annotations

import unittest
from ai.llm_client import CallableLLMClient, LLMRequest, LLMResponse
from ai.code_analyzer import CodeAnalyzer, CodeAnalyzerConfig, FindingCategory

def _fake_completion(request: LLMRequest) -> LLMResponse:
    # Check if user_roles is in the prompt
    if "{user_roles}" in request.prompt or "anonymous, authenticated_user, administrator" in request.prompt:
        return LLMResponse(content="Role-based analysis: Anonymous cannot access, but Authenticated User can via IDOR.", confidence=0.9)
    return LLMResponse(content="General analysis.", confidence=0.7)

class TestCodeAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.client = CallableLLMClient(provider_name="test", completion_callable=_fake_completion)
        self.config = CodeAnalyzerConfig(
            min_static_confidence=0.1,
            min_llm_confidence=0.1,
            constraints=["no hallucination"],
            prompt_template="Rule {rule_id}: {description} | Matched at line {line_number}: {matched_text} | Roles: {user_roles}",
            max_enrichment_calls=10,
            user_roles=["anonymous", "authenticated_user", "administrator"]
        )
        self.analyzer = CodeAnalyzer(llm_client=self.client, config=self.config)

    def test_static_scan_detects_idor(self) -> None:
        code = "user = User.objects.get(id=request.json['id'])"
        insights = self.analyzer.analyze(code)
        
        self.assertTrue(any("LOG001" in i.description for i in insights))
        self.assertTrue(any("Role-based analysis" in i.description for i in insights))

    def test_static_scan_detects_auth_bypass(self) -> None:
        code = "@app.route('/admin')\ndef admin_dashboard():\n    return 'sensitive data'"
        # Note: the regex expects a newline and then the def without specific decorators
        insights = self.analyzer.analyze(code)
        
        self.assertTrue(any("AUT001" in i.description for i in insights))

    def test_role_simulation_in_prompt(self) -> None:
        code = "user = User.objects.get(id=id)"
        # We need to trigger the IDOR rule
        code = "User.objects.get(id=123)"
        insights = self.analyzer.analyze(code)
        
        self.assertTrue(len(insights) > 0)
        # The fake completion checks for roles string in prompt
        self.assertIn("Role-based analysis", insights[0].description)

if __name__ == "__main__":
    unittest.main()
