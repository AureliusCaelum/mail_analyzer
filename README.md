# Mail Analyzer

Mail Analyzer scans incoming emails, evaluates potential threats using rule-based and machine-learning techniques, and presents results in a desktop GUI.

## Features
- Connectors for Outlook, Gmail, and Exchange
- Hybrid threat analysis with heuristics and scikit-learn models
- Optional local AI enrichment via HTTP APIs
- PyQt6 interface with dashboards and reports

## Installation
1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Optionally install development tools:
   ```bash
   pip install -e .[dev]
   ```

## Usage
Run the GUI entry point:
```bash
python -m gui.main_window
```

## Documentation
Additional documents live in the [`docs/`](docs/) directory:
- [Project Overview](docs/project_overview.md)
- [Request Flow](docs/request_flow.md)

## Testing
Execute the full test suite and linter from the repository root:
```bash
pytest
flake8 analyzer gui tests
```
