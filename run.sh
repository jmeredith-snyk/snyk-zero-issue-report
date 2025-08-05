#!/bin/bash

# Activate virtual environment and run the script
source venv/bin/activate
python3 snyk_issue_reporter.py "$@" 