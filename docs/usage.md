# AI Bug Hunter Usage Guide

Welcome to the **Raven AI Bug Hunting Ecosystem**! This guide will walk you through setting up and running your first automated security scan using the integrated AI-augmented pipeline.

---

## 🏗️ 1. Installation Steps

### Prerequisites
*   Python 3.10 or higher
*   [Playwright](https://playwright.dev/python/docs/intro) (for headless crawling)
*   Internet connection (for AI analysis and external scanning templates)

### Step-by-Step Install
1. **Clone or Download**: Ensure the Raven AI files are extracted to your local directory.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

---

## 🌐 2. Environment Setup

Configure your scan in **`configs/settings.yaml`**:

*   **AI Providers**: Switch between `openai`, `openrouter`, or `local` (Ollama).
*   **Headless Crawling**: Enable `recon.headless_enabled` for SPA/JS-heavy applications.
*   **Bug Bounty Mode**: Enable `scan.bug_bounty_mode` to prioritize high-signal endpoints.
*   **Exploit Chaining**: Toggle `analysis.exploit_chaining_enabled` for multi-step attack discovery.

---

## 🚀 3. Running the Tool

### Standard Scan
```bash
python3 main.py --target example.com
```

### Advanced Features
*   **Replay Mode**: Discoveries now include `request_data` allowing you to re-execute payloads using the integrated `VulnerabilityReplayer`.
*   **Prioritization**: The engine automatically scores endpoints based on sensitive keywords (`admin`, `api`) and parameter complexity.

---

## 🔍 4. Scan Modes

| Mode | Command | Description |
|---|---|---|
| **Full (Default)** | `--mode full` | Subdomains → Headless Discovery → JS Analysis → Fuzzing → AI Reasoning → Chaining → Reporting. |
| **Quick** | `--mode scan` | Dives straight into vulnerability scanning on known endpoints. |
| **AI Only** | `--mode ai` | Re-analyzes existing results using configured LLM providers. |

---

## 📝 5. Understanding Output

Findings include:
*   **Reproducible Steps**: Automatically generated deterministic guides to recreate the bug.
*   **Evidence**: Raw HTTP request/response data used for confirmation.
*   **Confidence Score**: AI-backed assessment of finding reliability.
*   **Replay Data**: JSON-formatted request metadata for manual verification.

---

## 📂 6. Where Reports are Saved

Reports are exported to `reports/out/` by default.
*   **`findings.md`**: Technical report with reproduction steps and evidence.
*   **`interaction_log.json`**: Full trace of all HTTP interactions.
