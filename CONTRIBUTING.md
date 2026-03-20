# Contributing

Contributions are welcome! Here's how to get started.

## Setup dev environment

```bash
git clone https://github.com/V1D1AN/connector-malpedia-samples
cd connector-malpedia-samples
python -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
pip install flake8 black isort pytest pytest-cov
```

## Code style

This project uses **black** (formatter), **isort** (import sorter) and **flake8** (linter).

```bash
black --line-length=120 src/ tests/
isort --profile=black src/ tests/
flake8 src/ tests/ --max-line-length=120
```

## Running tests

```bash
pytest tests/ -v --cov=src/malpedia_samples
```

No live Malpedia or OpenCTI instance is required — all tests use mocks.

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Add or update tests
4. Run linters and tests locally
5. Open a pull request using the provided template

## Reporting bugs

Use the **Bug report** issue template. Please include logs and your connector configuration (with sensitive values redacted).
