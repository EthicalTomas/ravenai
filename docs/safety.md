# Raven AI Scope and Safety Guide

The **Raven AI security scanner** is a powerful tool designed for authorized bug hunting and security research. To ensure its safe and legal operation, all users must adhere to the following scope and safety guidelines.

# Safety and Responsibility

Raven AI is built with a "Safety First" philosophy to ensure that automated scanning remains non-destructive and highly accurate.

---

## 🛡️ 1. The "Require Proof" Rule

The most significant risk in AI-augmented security is **hallucinated vulnerabilities**. Raven AI mitigates this through a strict verification protocol:

1.  **AI Hypothesis**: AI identifies a potential lead based on fuzzy signals.
2.  **Deterministic Test**: The `ExploitExecutor` re-executes the exact request.
3.  **Evidence Confirmation**: The finding is only reported if the original evidence (e.g., a specific reflection or error) is present in the live response.

**No evidence = No report.**

---

## 🌐 2. Scope Enforcement

Our `ScopeManager` ensures that the tool never wanders outside its permitted boundaries:
- **Domain Locking**: Only targets explicitly defined in the configuration are processed.
- **Headless Isolation**: The `HeadlessCrawler` is restricted to the target domain, preventing it from crawling external links discovered in JS files.

---

## 🚀 3. Concurrency and Rate Limiting

To prevent accidental Denial of Service (DoS):
- **Max Workers**: Configurable thread counts in `scanner.max_workers`.
- **Request Delays**: Centrally managed by the `HTTPClient` (defaults to 30ms between requests).
- **Headless Limits**: Page navigation and intercepted network requests are throttled to ensure stability on the target server.

---

## 🔑 4. Token & Credential Safety

Raven AI identifies sensitive tokens (JWT, API Keys) using the `TokenExtractor`. These are stored temporarily in the `ExecutionContext` for local exploit chaining and are **never** transmitted to remote AI providers in raw form.

---

## 🛑 5. Avoid Scanning without Permission

Unauthorized scanning of systems is illegal in many jurisdictions and may be considered a hostile act. Before starting any scan:

1.  **Verify Possession**: Confirm that the target domain belongs to the entity you are authorized to scan.
2.  **Review the Bug Bounty Policy**: If testing via a public bug bounty program (e.g., HackerOne, Bugcrowd), ensure your scan follows their specific "Safe Harbor" and "Out of Scope" rules.
3.  **No-Go Targets**: Never scan government, medical, or critical infrastructure systems unless they are explicitly within your authorized engagement scope.

---

## ⚡ 3. Rate Limiting and Performance

Aggressive scanning can unintentionally disrupt services, causing a Denial of Service (DoS). To prevent this:

*   **Scheduler Configuration**: Adjust the `max_threads` and `delay_seconds` settings in `configs/settings.yaml` to match the target's capacity.
*   **Shared Infrastructure**: Be especially cautious when scanning shared hosting or Cloud environments, as high-frequency probes can impact other users on the same host.
*   **Production vs. Staging**: Whenever possible, perform deep fuzzing on staging or development environments rather than live production systems.

---

## ⚖️ 4. Legal Considerations

Security research is subject to various local and international laws (such as the CFAA in the United States or the GDPR in the EU).

*   **Identity**: Your probes will carry identifying headers (if configured). Ensure these accurately reflect who is conducting the test.
*   **Data Handling**: When the scanner discovers sensitive data (PII, credentials, etc.), handle it with extreme care and according to the reporting policy. Do not download large amounts of sensitive data.
*   **Reporting**: Follow the target's vulnerability disclosure policy (VDP) exactly. Reporting a finding to the wrong person or publicly disclosing it without permission may have legal consequences.

---

## ✅ Summary Checklist

- [ ] Do I have written permission or a valid bug bounty scope?
- [ ] Is my `configs/settings.yaml` configured to be respectful of the target's performance (Rate Limiting)?
- [ ] Have I double-checked the `ScopeManager` to prevent accidental out-of-scope probes?
- [ ] Have I read and understood the legal landscape of the target's jurisdiction?
