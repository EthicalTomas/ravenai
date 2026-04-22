# DATA STRUCTURES

MANDATORY OBJECTS:
- Target
- Endpoint
- Vulnerability
- ScanResult
- AIInsight

RULES:
- Use set for deduplication
- Use dict for indexing
- Use list for ordered results
- Use graph for relationships

STRICT RULE:
- Never pass raw strings between modules
- Always use structured objects

PERFORMANCE:
- Prefer O(1) lookups (dict, set)