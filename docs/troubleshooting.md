# Raven AI Troubleshooting Guide

This guide provides technical solutions for common issues encountered while setting up or running the **Raven AI pipeline**.

---

## 🏗️ 1. Fixing Import Issues

If you see an `ImportError` or `ModuleNotFoundError`, it is typically due to an incorrectly configured Python environment.

### Common Symptom: `ModuleNotFoundError: No module named 'scanner'`
*   **Cause**: You are attempting to run a script from inside a sub-folder rather than the project root.
*   **Fix**: Always run Raven AI from the base directory:
    ```bash
    # Correct
    python3 main.py --target example.com
    
    # Incorrect (from inside scanner/)
    python3 nuclei_wrapper.py
    ```
*   **Fix 2**: Ensure your `PYTHONPATH` includes the project root:
    ```bash
    export PYTHONPATH=$PYTHONPATH:.
    ```

---

## 🛠️ 2. Missing Tools (External Binaries)

Raven AI includes wrappers for `nuclei`, `ffuf`, and `sqlmap`. If these are not installed or in your PATH, the relevant scan stages will fail.

### Symptom: `[ERROR] nuclei binary not found`
*   **Fix**: Install the missing tool following the [Installation Guide](./installation.md).
*   **Verification**: Run `which nuclei` or `which ffuf` in your terminal. If it returns nothing, the tool is not installed or not in your system's PATH.
*   **Override**: You can explicitly specify the binary path for each tool in `configs/settings.yaml`.

---

## 🚀 3. Diagnosing Failed Scans

If a scan completes but finds no endpoints or vulnerabilities, or if it stops prematurely:

### Symptom: "Found 0 endpoints"
*   **Cause**: The target domain is unreachable, or the crawler is being blocked by a WAF.
*   **Fix**: Check your internet connection and verify the domain exists. Try running with a higher `delay_seconds` in `configs/settings.yaml` to be less aggressive.

### Symptom: "AI stage failed: Connection error"
*   **Cause**: Invalid API key or your AI provider (OpenAI, Anthropic, etc.) is currently down.
*   **Fix**: Verify your API credentials in `configs/settings.yaml` and check the provider's status page.

### Symptom: "Scanner timed out for endpoint X"
*   **Cause**: The target server is responding too slowly for the configured timeout.
*   **Fix**: Increase the `timeout_seconds` value in `configs/settings.yaml`.

---

## 📝 4. Using the Logs for Debugging

Raven AI keeps detailed logs to help you find precisely where a failure occurred.

1.  **Terminal Output**: Review the `[ERROR]` and `[WARNING]` messages in real-time.
2.  **Interaction Log**: Check `reports/[Target]/interaction_log.json`. This file contains the raw request and response for every probe sent, allowing you to see if the server is returning `403 Forbidden` or `429 Too Many Requests`.
3.  **Debug Logging**: Enable deep technical logs by setting the logging level to `DEBUG` in your environment or `configs/settings.yaml`.
