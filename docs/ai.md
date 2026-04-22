# Raven AI Intelligence Guide

The **AI Subsystem** is the heart of Raven AI's high-confidence scanning. It uses Large Language Models (LLMs) to reason about code, findings, and vulnerability context, transforming raw probe data into actionable security insights.

---

## 🤖 1. How AI is Used in the Pipeline

Raven AI does not just "blindly" scan; it uses intelligence at three critical stages.

### A. Payload Generation (`ai.PayloadGenerator`)
*   **Purpose**: To expand and target our initial injection vectors.
*   **Activity**: If a scanner finds an interesting endpoint, the AI generates context-aware payloads based on the URL structure and parameter names (e.g., generating specific SSRF probes if it sees a `?url=` parameter).

### B. Finding Analysis (`ai.ResponseAnalyzer`)
*   **Purpose**: High-confidence filtering.
*   **Activity**: Once a candidate vulnerability is found, the AI reviews the raw HTTP response to determine if it is a true positive or just an unusual server message. This significantly reduces noise.

### C. Reporting Enrichment (`ai.VulnClassifier`)
*   **Purpose**: Strategic context.
*   **Activity**: For each confirmed finding, the AI generates a technical summary, impact assessment, and remediation advice included in the final security report.

---


### Customizing Prompts
You can find and edit the intelligence templates in:
**`configs/settings.yaml`** (under the `ai.prompts` section).

*   **Deepen Analysis**: Change the `analysis_prompt` to ask for more detailed exploit paths.
*   **Change Tone**: Adjust the `report_prompt` to generate findings for a specific audience (e.g., developers vs. executives).

### Adding New Skills
To add a new AI capability (e.g., Prototype Pollution analysis):
1.  **Define a new prompt** in your YAML config.
2.  **Implement the caller** in a new `ai/` sub-module using the `CallableLLMClient`.
3.  **Integrate** it as a new `Stage` in the `core.Engine`.

---

## ⚙️ 4. AI Configuration

In `configs/settings.yaml`, you can tune the behavior of the AI subsystem:

*   **`model`**: Select your LLM provider and version (e.g., `openai/gpt-4-turbo`).
*   **`temperature`**: Set this to **0.0** or **0.1** for clinical, consistent security analysis.
*   **`max_tokens`**: Adjust based on how long or short you want the finding summaries to be.
