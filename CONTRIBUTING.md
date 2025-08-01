# Contributing Guidelines

Thank you for considering contributing to Mail Analyzer.

## Development Workflow
- Create readable, modular Python code.
- Use Google-style docstrings for public classes and functions.
- Prefer simple solutions and keep external dependencies minimal.
- Comment complex logic and cover edge cases.
- For GUI work, separate layout from logic and avoid global UI elements.

## Checks
Run linting and tests before every commit:

```bash
flake8 analyzer gui tests
pytest
```

## Pull Requests
- Use commit messages in the imperative mood.
- Summarize the changes in the pull request description and list executed checks.

Please refer to `AGENTS.md` for more details on repository structure and conventions.
