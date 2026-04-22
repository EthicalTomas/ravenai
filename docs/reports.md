# Raven AI Report Interpretation Guide

The final output of a **Raven AI security scan** is a `ReportBundle` that aggregates technical findings, AI-driven insights, and raw interaction data. This guide explains how to read and interpret these records.

---

## 🏗️ 1. Report Artifact Structure

Each scan generates three primary files in the output directory:

| Filename | Format | Intended Audience |
|---|---|---|
| **`scan_report.html`** | Dashboard | Stakeholders and Security Managers. |
| **`findings.md`** | Technical List | Developers and Security Researchers. |
| **`interaction_log.json`** | Raw Data | Deep technical analysis and integration. |

---

## 🔍 2. Core Field Definitions

Every vulnerability found is structured with specific metadata to help you prioritize remediation.

### Severity
Reflects the potential impact of the vulnerability on the system's security posture.
*   **Critical**: Full system compromise (e.g., Code Execution, SSRF into cloud metadata).
*   **High**: Significant data leak or unauthorized access (e.g., SQL Injection, XSS in sensitive areas).
*   **Medium**: Limited impact (e.g., Reflected XSS on low-value pages).
*   **Low**: Information disclosure or low-impact misconfigurations.
*   **Info**: General architectural or surface mapping observations.

### Confidence
A score from **0.0 to 1.0** reflecting the scanner's certainty that the finding is valid.
*   **1.0**: Confirmed with absolute evidence (e.g., matched an error message or reflected payload exactly).
*   **0.8+**: High likelihood of a vulnerability, though manual verification is recommended.
*   **0.5**: Potential finding based on a pattern, but requires significant review.

### Payload
The specific string or vector used during the probe to trigger the vulnerability. Use this to re-test the finding manually in your browser or a tool like `curl`.

---

## 🛠️ 3. How to Interpret Findings

When reviewing a finding in `findings.md` or the HTML report, focus on the following components:

### A. Endpoint Analysis
The report identifies the specific **URL**, **HTTP Method**, and **Parameters** where the issue was discovered. Ensure you are targeting the exact parameters mentioned.

### B. Evidence Logs
This section contains the raw snippet of the response (HTML, JSON, or Header data) that triggered the finding. It provides the "proof of concept" required to believe the scanner's report.

### C. AI Insight (If Enabled)
If the AI Logic Stage was executed, you will see a text summary explaining *why* the AI believes this is a risk and potentially suggesting a specific fix.

### D. Correlation Links
Raven AI uses its **Vector Memory** to link similar findings. If a vulnerability is found in one endpoint, the "Similar Findings" section will show you everywhere else the same pattern was detected, helping you identify systemic issues across the target.

---

## 📂 4. Where to Find Your Results

By default, Raven AI saves all reports in a timestamped folder inside the `reports/` directory:
`reports/[YYYY-MM-DD]_[Target]/`

You can overide this location using the `--output` CLI flag when starting a scan.
