# CONCURRENCY

USE:
- ThreadPoolExecutor for I/O tasks

RULES:
- Parallelize endpoint scanning
- Avoid shared mutable state
- Use locks if necessary

DATA SAFETY:
- Do not mutate shared objects unsafely