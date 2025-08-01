# Mail Analyzer

Mail Analyzer is a modular application for scanning and evaluating email messages for potential threats. It combines rule-based heuristics, machine learning, contextual analysis and clustering, and displays results in a PyQt6 desktop interface.

## Features
- Connectors for Outlook, Gmail and Exchange to retrieve emails.
- Threat analysis pipeline with rule checks, machine-learning models, context-aware evaluation, clustering and proactive defense.
- Feedback loop to adapt scoring with user input.
- Reporting engine generating PDF or Excel summaries.
- PyQt6-based interface with a threat dashboard and traffic light indicator.

## Installation
1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

Alternatively install the project as a package:

```bash
pip install .
```

## Usage
Run the GUI main window:

```bash
python gui/main_window.py
```

Emails will be fetched and analyzed automatically. Use the dashboard for insights and the report generator to export findings.

## Development
Run lint and tests before committing:

```bash
flake8 analyzer gui tests
pytest
```

Refer to `docs/project_overview.md` for architecture details and `docs/request_flow.md` for data flow.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License
Released under the [MIT License](LICENSE).
