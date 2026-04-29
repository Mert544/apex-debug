"""Quick test for AI integration without real API calls."""

from apex_debug.ai.client import AIClient
from apex_debug.ai.explainer import explain_finding
from apex_debug.ai.fixer import generate_fix
from apex_debug.core.finding import Finding, Severity


class MockClient:
    """Mock AI client for testing."""

    def __init__(self):
        self.api_key = "test"
        self.base_url = "http://mock"
        self.model = "mock-model"

    def chat(self, system: str, user: str) -> str:
        return f"MOCK_RESPONSE: {user[:50]}..."


def test_explain():
    finding = Finding(
        id="SEC-001",
        file="app.py",
        line=42,
        severity=Severity.CRITICAL,
        category="security",
        title="Dangerous eval/exec usage",
        message="eval() is dangerous",
        snippet="eval(user_input)",
    )
    client = MockClient()
    result = explain_finding(finding, client)
    assert "MOCK_RESPONSE" in result
    print("explain_finding: OK")


def test_fix():
    finding = Finding(
        id="SEC-001",
        file="app.py",
        line=42,
        severity=Severity.CRITICAL,
        category="security",
        title="Dangerous eval/exec usage",
        message="eval() is dangerous",
        snippet="eval(user_input)",
    )
    client = MockClient()
    result = generate_fix(finding, client)
    assert "MOCK_RESPONSE" in result
    print("generate_fix: OK")


if __name__ == "__main__":
    test_explain()
    test_fix()
    print("All AI integration tests passed.")
