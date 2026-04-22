# ERROR HANDLING

RULES:
- Never crash the pipeline
- Catch exceptions per module
- Log errors properly

RETRY LOGIC:
- Retry failed network calls
- Skip failing endpoints safely

FORBIDDEN:
- Silent failures
- Bare except blocks