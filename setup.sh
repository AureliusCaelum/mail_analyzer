#!/usr/bin/env bash
set -e

# Upgrade pip to ensure latest package management features
python -m pip install --upgrade pip

# Install runtime dependencies
python -m pip install \
    numpy \
    pandas \
    matplotlib \
    joblib \
    httpx \
    requests \
    schedule \
    scikit-learn \
    PyQt6

# Install development tools
python -m pip install \
    pytest \
    flake8
