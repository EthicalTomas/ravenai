# SYSTEM ARCHITECTURE

Architecture:
Recon → Scanner → AI → Analysis → Report

RULES:
- Each module must be independent
- Use pipeline pattern
- No tight coupling between modules

DATA FLOW:
- Input and output must always be structured objects

FORBIDDEN:
- Direct module-to-module dependencies without interfaces