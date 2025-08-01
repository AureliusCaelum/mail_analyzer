# Documentation Index

This directory contains supplemental documentation for Mail Analyzer.

## Contents
- [Project Overview](project_overview.md): architecture and component summary
- [Request Flow](request_flow.md): end-to-end message processing
- [Installation](#installation)
- [Running Tests](#running-tests)

## Installation
Follow the steps from the repository README to install dependencies. Afterwards, configure email credentials in `config/settings.py` as needed.

## Running Tests
From the project root execute:
```bash
pytest
flake8 analyzer gui tests
```
