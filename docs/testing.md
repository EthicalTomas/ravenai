# Raven AI Testing Guide

Ensuring a robust and reliable security pipeline is critical. Raven AI uses the **pytest** framework for all automated testing, from core models to high-level discovery and analysis stages.

---

## 🚀 1. How to Run Tests

Before submitting any changes, run the full test suite to ensure no regressions have been introduced.

### Running all tests
Execute this command from the project root:
```bash
pytest
```

### Running specific module tests
To test a specific package or file:
```bash
pytest tests/test_recon.py
```

### Verbosity & Debugging
Use the `-v` flag for detailed output or `-s` to see log output even for passed tests:
```bash
pytest -v -s
```

---

## 📝 2. Writing New Tests

New tests should be added to the `tests/` directory, following a naming convention that mirrors the module being tested (e.g., `tests/test_scanner.py` for `scanner/`).

### Standard Test Pattern
1. **Use Fixtures**: Define reusable components using `@pytest.fixture`.
2. **Mock Network Access**: Always use `unittest.mock` to prevent tests from sending real HTTP requests.
3. **Assert Outcomes**: Use clear assertions to verify both success and failure cases.

```python
import pytest
from unittest.mock import MagicMock
from scanner import XSSScanner

@pytest.fixture
def mock_client():
    return MagicMock()

def test_xss_scanner_finding(mock_client):
    scanner = XSSScanner(client=mock_client, payloads=["<script>alert(1)</script>"])
    
    # Mock a successful injection response
    mock_response = MagicMock(status_code=200, text="<script>alert(1)</script>")
    mock_client.request.return_value = mock_response

    result = scanner.scan_endpoint(my_endpoint)
    
    # Verify the finding was recorded
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].vuln_type == "xss"
```

---

## 📂 3. Test Structure

| Directory | Content Purpose |
|---|---|
| **`tests/test_recon.py`** | Discovery, crawler, and parameter enumeration logic. |
| **`tests/test_scanner.py`** | Custom vulnerability scanners (XSS, SQLi, SSRF). |
| **`tests/test_data.py`** | Schema validation and model integrity checks. |
| **`tests/test_core.py`** | Pipeline engine, scheduler, and configuration loading. |
| **`tests/test_analysis.py`** | Correlation, deduplication, and risk scoring. |

---

## 📏 4. Testing Standards

*   **Isolation**: Every test should be isolated. Never rely on the state of a previous test run.
*   **Coverage**: Target 1:1 coverage for all public methods in the security and AI modules.
*   **Edge Cases**: Always include a "negative" test case (e.g., how the system handles malformed URLs or timeouts).
*   **Mocking**: Never perform real network requests in automated tests. Use the `HTTPClient` mocks to simulate responses.
