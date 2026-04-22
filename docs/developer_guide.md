# Raven AI Developer Guide

Welcome to the **Raven AI developer ecosystem**! This guide provides a technical walkthrough for extending the pipeline, implementing new security scanners, and ensuring your contributions meet our high-performance standards.

---

## 📂 1. Project Structure Explanation

Raven AI is designed as a modular library of security and AI components. Every major feature lives in its own dedicated package:

| Package | Purpose |
|---|---|
| **`ai`** | AI intelligence, LLM clients, and vulnerability classification. |
| **`analysis`** | Risk scoring, semantic correlation, and deduplication logic. |
| **`configs`** | Centralized YAML settings, scanner payloads, and prompts. |
| **`core`** | Pipeline orchestration, scheduler, and engine stages. |
| **`data`** | Validated schemas, models, and vector memory. |
| **`recon`** | Attack surface discovery and parameter spidering components. |
| **`scanner`** | Custom vulnerability scanners and fuzzing orchestrators. |
| **`integrations`** | Connectors for third-party tools (Burp, FFUF, etc.). |
| **`utils`** | Foundational HTTP, parsing, and logging utilities. |
| **`reports`** | Professional report builders, exporters, and templates. |

---

## 🏹 2. How to Add New Scanners

Adding a new vulnerability scanner (e.g., GraphQL or Prototype Pollution) follows a standardized pattern to ensure it integrates seamlessly with the `FuzzingEngine`.

### Step-by-Step Implementation
1. **Create the Scanner**: Add a new file in `scanner/your_scanner.py`.
2. **Define the Dataclass**: Use `@dataclass(slots=True)` and include the `HTTPClient` for communication.
   ```python
   from dataclasses import dataclass
   from utils import HTTPClient
   from data import ScanResult

   @dataclass(slots=True)
   class PrototypeScanner:
       client: HTTPClient
       payloads: list[str]
       
       def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
           # 1. Injected payload into endpoint parameters
           # 2. Perform the request using self.client
           # 3. Analyze response and return ScanResult
   ```
3. **Register in Init**: Add your scanner to `scanner/__init__.py`.
4. **Update the Engine**: Add a task for your new scanner inside `scanner/fuzzing_engine.py`.

---

## 🤖 3. How to Extend AI Modules

Raven AI uses an intelligence layer to enrich scan data. You can expand this by building new analysis stages (e.g., deep business logic analysis).

1. **Implement the Logic**: Use the `CallableLLMClient` to interact with your configured model.
2. **Model your Insights**: Use `ScanResult` metadata to store AI-generated reasoning.
3. **Data Integrity**: Ensure any new intelligence flags are documented in `data/schemas.py` if they need to be persisted to long-term storage or reports.

---

## 📏 4. Code Standards

To maintain high performance and readability, all contributions must follow these rules:

### (A) Use Dataclasses with Slots
Always use `@dataclass(slots=True)` for models and stateful components to minimize memory overhead during large-scale scans.

### (B) Type Hinting (Strictly Enforced)
Every function must have complete type hints for arguments and return values.
```python
def analyze_vulnerability(finding: Vulnerability) -> float:
    # Good
```

### (C) Centralized Communication
**Crucial Rule**: Never use the `requests` library directly in your modules. Always use the `utils.HTTPClient` injected into your class to benefit from managed retries, timeouts, and logging.

### (D) Zero-Dependency Logic
Keep discovery and analysis modules focused on their specific security logic. If you need complex data structures or validation, use the `data` package.

---

## ✅ 5. Final Checklist before PR

1.  **Tests**: Add a new test case in `tests/` (we use **pytest**).
2.  **Relative Imports**: Use relative imports (`from . import X`) for any logic within the same package.
3.  **No Hand-Coded Payloads**: If your scanner needs payloads, add them to `configs/payload.yaml`.
