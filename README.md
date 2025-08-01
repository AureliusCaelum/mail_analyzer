# Mail Analyzer

Mail Analyzer is a modular application for scanning and evaluating email messages for potential threats. It combines rule-based heuristics, machine learning, contextual analysis and clustering, and displays results in a PyQt6 desktop interface.

## Features

* Connectors for Outlook, Gmail and Exchange to retrieve emails.
* Threat analysis pipeline with rule checks, machine-learning models, context-aware evaluation, clustering and proactive defense.
* Feedback loop to adapt scoring with user input.
* Reporting engine generating PDF or Excel summaries.
* PyQt6-based interface with a threat dashboard and traffic-light indicator.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-repo/mail-analyzer.git
   cd mail-analyzer
   ```
2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   ```
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
4. (Optional) Install development extras:

   ```bash
   pip install -e .[dev]
   ```

## Usage

Run the GUI main window:

```bash
python -m gui.main_window
```

Emails will be fetched and analyzed automatically. Use the dashboard for insights and the report generator to export findings.

## Development

Before committing, ensure code quality and test coverage:

```bash
flake8 analyzer gui tests
pytest
```

Additional architectural and data-flow documentation is in the `docs/` directory.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute, report issues, and submit pull requests.

## License

Released under the [MIT License](LICENSE).
