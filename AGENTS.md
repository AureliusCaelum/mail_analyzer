# Contributor Guide

## Repository Overview
- `analyzer/` – core email analysis modules such as scanners, threat detection, and reporting.
- `analyzer/email_clients/` – connectors for specific mail providers.
- `config/` – configuration helpers.
- `gui/` – Kivy-based user interface components.
- `tests/` – pytest suite covering the modules above.

## Development Guidelines
- Write readable, modular Python and include Google-style docstrings for public classes and functions.
- Prefer simple, robust solutions and minimize external dependencies.
- Use descriptive variable and function names; comment complex logic and consider edge cases.
- For Kivy code, separate layout from logic and avoid placing UI elements in the global scope.
- For machine-learning code, document preprocessing steps, use `scikit-learn` for prototypes, and save metrics and artifacts reproducibly.

## Testing and Linting
- Run `pytest` from the repository root to execute unit tests.
- Run `flake8 analyzer gui tests` to lint the codebase.
- Ensure all tests and lint checks pass before committing changes.

## PR Instructions
- Use commit messages in the imperative mood.
- Pull request titles should follow the format `[mail_analyzer] <summary>`.
- In the PR description, summarize the changes and list the tests or lint commands executed.
