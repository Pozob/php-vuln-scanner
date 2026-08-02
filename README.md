# php-vuln-scanner

A static analysis (SAST) scanner for PHP applications, written for a bachelor thesis.
It parses PHP source with tree-sitter and runs modular checks for selected OWASP Top 10
categories.

## Requirements

- Python 3.12 or newer

All other dependencies (tree-sitter, tree-sitter-php, PyYAML) are installed automatically.

## Installation

From the project root:

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e .
```

This installs the `phpscan` command. To also install the test dependencies:

```bash
pip install -e ".[dev]"
```

## Usage

Scan a directory or a single file:

```bash
phpscan scan path/to/folder
phpscan scan path/to/file.php
```

Example output:

```
phpscan 0.1.0 scanned 'tests/fixtures/deprecated_crypto.php'
PHP files found:  1
parsed:           1
modules run:      a02_misconfiguration, a04_crypto_failures, a05_injection
findings:         2 (high: 1, medium: 1)
by category:      A04:2025: 2

high severity:
  deprecated_crypto.php:4 - A04-CRYPTO-002  [CWE-327]  Broken cipher or mode (DES/RC4/ECB) used in an openssl_* call.

medium severity:
  deprecated_crypto.php:3 - A04-CRYPTO-001  [CWE-327]  Use of the deprecated mcrypt API (removed in PHP 7.2).
```

### Options for `scan`

| Option           | Description                                                                                                    |
|------------------|----------------------------------------------------------------------------------------------------------------|
| `--format`, `-f` | Output format: `term` (default), `json` or `html`. Can be multiple times                                       |
| `--output`       | Path of the report file for `json`/`html`. Defaults to `<target>.phpscan.json` / `<target>.phpscan.html`.      |
| `--modules`      | Comma separated list of module ids to run, e.g. `--modules a05_injection`. Default is every discovered module. |
| `--config-dir`   | Directory with config overrides (default: `./config`).                                                         |
| `--verbose`      | More detailed terminal output and debug logging.                                                               |

Writing a JSON and an HTML report at once:

```bash
phpscan scan path/to/folder -f json -f html
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan finished, no findings |
| `1` | Error (target missing, invalid config, report could not be written) |
| `2` | Scan finished and findings were reported |

## Modules

Each check lives in its own folder or zip file under `modules/`. 

Your can list the discovered ones with

```bash
phpscan modules list
```

To run only a subset of them:

```bash
phpscan scan path/to/folder --modules a02_misconfiguration,a04_crypto_failures
```

### Customizing a module

Every module ships with a default configuration. 
To easily change it, publish a copy into your config directory and edit that file:

```bash
phpscan modules publish a05_injection
```

This writes `config/a05_injection.yaml`, which then replaces the module's default
configuration on the next scan. Pass `--force` to overwrite an existing file while publishing.

### Scan settings

Which files are scanned can be adjusted with an optional `config/core.yaml`:

```yaml
php_extensions: [".php", ".php3", ".php4", ".php5", ".phtml", ".inc"]
exclude_dirs: ["vendor", "node_modules", ".git"]
```

Both keys are optional and fall back to the values shown above.

## Tests
To run the test, just run
```bash
pytest
```
