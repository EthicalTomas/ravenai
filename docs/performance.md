# Raven AI Performance Guide

Running a multi-stage security pipeline requires balancing scanning speed with target stability and system resources. This guide explains how to tune **Raven AI** for high-performance discovery.

---

## ⚡ 1. Optimizing Concurrency

Raven AI uses a multi-threaded `Scheduler` to distribute scanning and AI analysis tasks.

### Thread Management
You can control the concurrency level in `configs/settings.yaml`.
*   **`max_threads`**: Determines how many simultaneous network probes are sent. (Default: 5).
*   **Scale Up**: For large enterprise targets with robust infrastructure, you can increase this to 20 or more.
*   **Scale Down**: For fragile or rate-limited targets, reduce this to 1-2 threads to avoid accidental service disruption.

### Resource Isolation
Each stage (Recon, Scanning, AI) has its own task distribution.
*   **Scanning Stage**: Typically high-volume, low-CPU.
*   **AI Stage**: Low-volume, high-latency.
*   **Analysis Stage**: High-CPU (Vector search), zero-network.

---

## 🛡️ 2. Avoiding Duplicate Scans

To ensure efficiency, Raven AI includes a **ScanCache** system that prevents redundant work.

### Deduplication Logic
The `data.storage.ScanCache` generates a unique fingerprint for every request based on:
1.  **Target URL**
2.  **HTTP Method**
3.  **Parameter Keys**
4.  **Payload Signatures**

### Workflow Advantage
If a scanner attempts to probe the same endpoint with the same payload twice, the `FuzzingEngine` will skip the second request and return the cached result. This is especially useful when running multiple scanners (XSS + SQLi) that may hit overlapping endpoints.

---

## 🛑 3. Tuning Rate Limits

To be a "good citizen" on the network and avoid being blocked by WAFs (Web Application Firewalls), fine-tune your request frequency.

### Key Settings in `configs/settings.yaml`
*   **`delay_seconds`**: The mandatory wait time between requests sent by a single thread. (Default: 0.1s).
*   **`max_retries`**: How many times the `HTTPClient` will attempt a failed request before giving up. (Default: 3).
*   **`backoff_factor`**: Determines how long to wait between retries (uses an exponential backoff formula).

---

## 🧠 4. AI & Analysis Performance

AI-driven reasoning is the most time-consuming part of the pipeline.

### Performance Strategy
*   **Enable AI for Findings Only**: By default, Raven AI only sends *discovered* vulnerabilities to the LLM for reasoning, rather than every raw request.
*   **Batch Analysis**: The AI Stage groups results to minimize the number of API calls to your provider (OpenAI, Claude, etc.).
*   **Vector Space Memory**: Using the FAISS backend (if installed) ensures that even with thousands of vulnerabilities, the similarity correlation stage remains extremely fast (sub-millisecond search).

---

## ✅ Performance Checklist

- [ ] Match `max_threads` to the target's capacity.
- [ ] Check `ScanCache` logs to see how many redundant requests were prevented.
- [ ] Ensure `delay_seconds` is sufficient to bypass basic rate-limiting detection.
- [ ] Use the FAISS backend in `VectorStore` for large datasets.
