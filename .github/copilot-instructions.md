# Copilot Workspace Instructions

## Principles
- Follow modular, testable, and secure coding practices.
- Use advanced YAML config for all operational parameters; avoid hardcoded values.
- Enforce input validation, scope control, and structured logging.
- Prefer dataclasses and type hints for all structured data.
- Use thread-safe concurrency and non-blocking rate limiting.
- Integrate AI/ML features as modular, testable components.
- All CLI, config, and logging interfaces must be user-overridable.

## Workflow
1. Discover conventions: Check README.md, skills/, and utils/ for project patterns.
2. Use provided config, logging, and validation utilities—do not reimplement.
3. For new modules:
   - Place in the appropriate domain folder (analysis/, reports/, integrations/, scanner/, data/, core/, utils/).
   - Add unit tests in tests/.
   - Register in main.py or via config if pipeline-related.
4. For external tool integration, wrap subprocesses safely and return structured results.
5. For rate limiting, use utils/rate_limiter.py.
6. For memory/AI, use data/memory/ and ai/ modules.
7. All new features must be covered by tests and documented in README.md.

## Anti-patterns
- No hardcoded secrets, endpoints, or operational values.
- No direct subprocess calls outside integrations/.
- No global state except for config and logger singletons.
- No blocking waits in concurrency code.
- No untyped or loosely typed data structures.

## Example Prompts
- "Add a new scanner module for XSS detection."
- "Integrate a new AI model for vulnerability triage."
- "Update the config system to support per-module timeouts."
- "Write tests for the rate limiter."

## Next Steps
- Propose agent customizations for specialized workflows (e.g., /create-agent pentest, /create-skill ai-memory).
- Suggest applyTo-based instructions for frontend/backend/tests if the workspace grows.
