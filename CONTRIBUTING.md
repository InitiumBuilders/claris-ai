# Contributing to Claris AI

Claris is MIT open source. Contributions welcome — especially:
- New injection patterns (via zero_day_hunter pipeline)
- OWASP LLM coverage improvements
- Agent-specific attack vectors
- Defense protocol enhancements

## How to Contribute

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make changes + add tests
4. Run: `python3 scripts/injection_guard.py --quick` (must pass)
5. Submit a PR with clear description

## Pattern Submissions
New bypass patterns go through the zero_day_hunter pipeline:
```bash
python3 scripts/zero_day_hunter.py --analyze "your bypass text"
python3 scripts/zero_day_hunter.py --pending
```

## Security Issues
Please report security vulnerabilities privately to: initiumbuilders@gmail.com
Do NOT open public issues for security findings.

## Philosophy
*Semper Fortis* — Always Strong. The security of one affects the security of all.
