# API DESIGN

RULES:
- Use clean function interfaces
- Input and output must be typed

EXAMPLE:
scan(endpoint: Endpoint) -> ScanResult

FORBIDDEN:
- Functions returning mixed types
- Hidden side effects