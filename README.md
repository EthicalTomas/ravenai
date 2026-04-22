# Raven AI

Raven AI is a modular, AI-augmented vulnerability discovery ecosystem designed for modern application security teams. It streamlines the entire bug hunting lifecycle—integrating high-performance reconnaissance, distributed fuzzing, and AI-powered deep analysis into a single resilient pipeline.

## 🚀 Key Features

*   **Intelligence-First Scanning**: Leverages LLMs for deep reasoning on source code and finding classification, reducing noise and prioritizing critical risks.
*   **Vector Memory System**: Semantic similarity search powered by FAISS, allowing Raven AI to correlate vulnerability patterns across disparate endpoints and subdomains.
*   **Resilient Architecture**: A modular scheduler with built-in retries and graceful "skip-on-failure" semantics to ensure stable pipeline execution.
*   **Comprehensive Payloads**: Centralized, YAML-driven detection database for XSS, SQLi, SSRF, and Nuclei templates.
*   **Strict Integrity**: All data—from targets to findings—is enforced through a zero-dependency, type-safe schema layer.
*   **Interoperability**: First-class support for Burp Suite Professional reports and raw HTTP message ingestion.

## 🏗️ Pipeline Architecture

Raven AI operates as a unified six-stage execution chain:

1.  **Reconnaissance**: Subdomain enumeration and automated endpoint discovery.
2.  **Param Discovery**: Static HTML parsing and active wordlist-based parameter spidering.
3.  **Fuzzing Engine**: Multi-threaded, protocol-aware scanning for common web vulnerabilities.
4.  **AI Analysis**: LLM-assisted insecure pattern detection and finding enrichment.
5.  **Correlator & Scoring**: Semantic and logic-based finding correlation paired with impact-weighted risk scoring.
6.  **Report Factory**: Generation of high-impact, structured security reports in multiple formats.

## 📦 Project Structure

```text
raven-ai/
├── ai/             # AI Analysis & LLM integration modules
├── analysis/       # Risk scoring, correlation, and deduplication logic
├── configs/        # YAML settings, scanner payloads, and prompts
├── core/           # Pipeline engine, scheduler, and configuration loader
├── data/           # Validated schemas, models, and vector memory
├── recon/          # Attack surface discovery and parameter spidering
├── scanner/        # Fuzzing engine and specialized security scanners
├── integrations/   # Burp Suite and third-party tool connectors
├── reports/        # Report builders, exporters, and templates
└── utils/          # Robust HTTP clients and data parsers
```

## 🛠️ Installation

1.  **Dependencies**: Install the core requirements:
    ```bash
    pip install -r requirements.txt
    ```
2.  **Configuration**: Define your target, secrets, and scanner sensitivity in:
    - `configs/settings.yaml` (System and AI configuration)
    - `configs/payload.yaml` (Scanner detection vectors)

## 💻 CLI Usage

The primary entry point is `main.py`. Use the following flags to manage the pipeline execution:

```bash
# Full pipeline scan against a single domain
python3 main.py --target example.com

# Override the default output directory for reports
python3 main.py --target internal.corp --output ./scans/internal

# Run in a specific pipeline mode (full, recon, scan, ai, analysis, report)
python3 main.py --target api.dev --mode scan
```

## 👨‍💻 Developer Integration

Raven AI is built with a clean import system, allowing you to use individual modules directly in your own tools:

```python
from scanner import SSRFScanner, XSSScanner
from utils import HTTPClient
from data import Target

# Initialize components
client = HTTPClient(config=my_config)
scanner = SSRFScanner(client=client, payloads=["http://127.0.0.1"])

# Execute targeted discovery
target = Target(domain="api.example.com")
results = scanner.scan_endpoint(my_endpoint)
```
