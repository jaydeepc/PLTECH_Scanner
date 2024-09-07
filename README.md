# PLTECH Scanner

PLTECH Scanner is a comprehensive command-line security scanner for checking various security measures in code repositories. It supports multiple programming languages and provides detailed reports on potential vulnerabilities.

## Features

- String Input Sanitization (SQL Injection, XSS, DOM-based Injection)
- CORS Configuration Analysis
- Authentication Implementation Checks
- Authorization Setup Verification
- Detailed Terminal and HTML Reports

## Installation

To install PLTECH Scanner globally, use npm:

```
npm install -g pltech-scanner
```

## Usage

After installing the scanner, you can use it from any directory by running:

```
pltech-scanner [options] <path-to-repository>
```

### Options

- `--all`, `-a`: Run all scans
- `--string`, `-s`: Run string input sanitization scan
- `--cors`, `-c`: Run CORS configuration scan
- `--auth`, `-u`: Run authentication scan
- `--authz`, `-z`: Run authorization scan
- `--no-open`, `-n`: Do not automatically open the HTML report

### Examples

Run all scans on the current directory:
```
pltech-scanner --all .
```

Run only string input sanitization and CORS configuration scans:
```
pltech-scanner --string --cors /path/to/your/repo
```

Run authentication and authorization scans without opening the HTML report:
```
pltech-scanner --auth --authz --no-open /path/to/your/repo
```

## Reports

The scanner generates two types of reports:

1. A detailed, colorful terminal report that provides an overview of the scan results.
2. An interactive HTML report with charts and detailed vulnerability information.

By default, the HTML report is automatically opened in your default web browser after the scan. You can disable this behavior with the `--no-open` option.

## Supported Languages

The scanner supports analysis of the following languages:

- JavaScript
- Python
- PHP
- Java

## Note

The scanner ignores common package and build directories such as `node_modules`, `lib`, `vendor`, `dist`, `build`, `.venv`, `venv`, `env`, `__pycache__`, and `.git`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the ISC License.