# Password & Credential Security Audit Suite

An advanced Python-based toolkit for **controlled password-security auditing and credential attack simulation**. The project combines password intelligence, hash analysis, dictionary and brute-force simulation, mutation-based candidate generation, crack-time estimation, and structured security reporting into a single laboratory-oriented workflow.

> **Authorized Use Only:** This project is designed for controlled laboratory environments, educational purposes, and authorized security assessments. Do not use it against accounts, systems, credentials, or data without explicit permission.

---

## Overview

The **Password & Credential Security Audit Suite** provides a modular environment for evaluating password security and simulating common credential attack techniques without targeting real-world unauthorized systems.

The suite can:

* Analyze password strength and predictability
* Identify common password patterns
* Identify and analyze supported password hash formats
* Generate password mutations
* Load and normalize dictionary wordlists
* Perform controlled dictionary attacks
* Perform bounded brute-force simulations
* Estimate password-cracking time
* Build structured audit findings
* Generate JSON and human-readable security reports
* Execute complete end-to-end password audit workflows

The architecture is intentionally modular so individual components can be tested, extended, and reused independently.

---

## Key Features

### Password Intelligence

The password analysis engine evaluates characteristics such as:

* Password length
* Character composition
* Entropy estimation
* Predictability
* Common-password patterns
* Short-password detection
* Keyboard patterns
* Year-based patterns
* Leetspeak transformations
* Overall security scoring

The analyzer produces structured results that can be incorporated into audit reports.

---

### Hash Analysis

The hash analysis component provides controlled analysis of supported password-hash representations.

Currently supported algorithm families include:

* MD5
* SHA-1
* SHA-256
* SHA-512

The system can identify hash formats and provide associated analysis metadata such as confidence, security rating, and salted-format information where applicable.

---

### Dictionary Attack Simulation

The dictionary attack module provides a controlled mechanism for testing passwords against an authorized laboratory target.

The candidate pipeline supports:

* Wordlist loading
* Duplicate removal
* Blank-value filtering
* Candidate limits
* Candidate normalization
* Controlled dictionary matching

This allows password-security testing without requiring interaction with live authentication systems.

---

### Brute-Force Simulation

The brute-force engine provides bounded laboratory simulation of exhaustive candidate searching.

Capabilities include:

* Configurable character sets
* Configurable maximum password length
* Search-space calculation
* Candidate-attempt limits
* Match detection
* Termination tracking
* Attempts-per-second measurement
* Crack-time estimation

The simulator is intentionally designed around controlled local testing rather than live account attacks.

---

### Mutation Engine

The mutation engine generates additional password candidates from authorized laboratory input.

Examples of mutation strategies include:

* Case variations
* Numeric suffixes
* Numeric prefixes
* Common substitutions
* Symbol variations
* Leetspeak transformations

Generated candidates can be passed through the candidate pipeline for controlled attack simulation.

---

### Crack-Time Estimation

The crack-time estimator provides an approximate measurement of how long a password search could take based on:

* Candidate-space size
* Estimated attempts per second
* Search strategy

These estimates are intended for security-analysis purposes and should not be interpreted as guarantees of real-world cracking performance.

---

### Security Reporting

The reporting subsystem builds structured audit reports containing:

* Audit identification
* Target/hash information
* Password-analysis results
* Hash-analysis results
* Attack-simulation results
* Findings
* Recommendations
* Overall risk information

Reports can be generated in:

* JSON
* Human-readable text
* Combined output formats

Generated audit files are excluded from version control by the project's `.gitignore`.

---

## Architecture

```text
Password-Credential-Security-Suite/
│
├── config/
│   ├── __init__.py
│   └── settings.py
│
├── core/
│   ├── __init__.py
│   ├── attack_engine.py
│   ├── candidate_pipeline.py
│   ├── cli_utils.py
│   ├── hash_utils.py
│   ├── lab_workflow.py
│   └── validators.py
│
├── modules/
│   ├── __init__.py
│   ├── brute_force_simulator.py
│   ├── crack_time_estimator.py
│   ├── dictionary_attack.py
│   ├── hash_analyzer.py
│   ├── mutation_engine.py
│   ├── password_strength.py
│   └── wordlist_loader.py
│
├── reporting/
│   ├── __init__.py
│   ├── audit_builder.py
│   ├── audit_models.py
│   └── report_writer.py
│
├── tests/
│   ├── __init__.py
│   ├── test_attacks.py
│   ├── test_dictionary_attack.py
│   ├── test_end_to_end.py
│   ├── test_intelligence.py
│   ├── test_main.py
│   └── test_reporting.py
│
├── wordlists/
│   └── lab_dictionary.txt
│
├── main.py
├── .gitignore
└── README.md
```

---

## Technology Stack

* **Language:** Python
* **Testing:** pytest
* **Version Control:** Git
* **Repository:** GitHub
* **Architecture:** Modular Python package structure
* **Output:** JSON and text audit reports

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Shaikhshariq-tech/Password-Credential-Security-Suite.git
cd Password-Credential-Security-Suite
```

Create a virtual environment:

### Windows

```cmd
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the testing dependency:

```bash
python -m pip install pytest
```

---

## Running the Application

From the project root:

```bash
python main.py
```

The application launches the controlled laboratory audit interface and provides access to the implemented password-security analysis workflows.

---

## Running the Test Suite

Run all tests:

```bash
python -m pytest -v
```

Individual test groups can also be executed.

### Intelligence tests

```bash
python -m pytest tests/test_intelligence.py -v
```

### Attack tests

```bash
python -m pytest tests/test_attacks.py -v
```

### Dictionary attack tests

```bash
python -m pytest tests/test_dictionary_attack.py -v
```

### Reporting tests

```bash
python -m pytest tests/test_reporting.py -v
```

### Main workflow tests

```bash
python -m pytest tests/test_main.py -v
```

### End-to-end tests

```bash
python -m pytest tests/test_end_to_end.py -v
```

---

## Testing Strategy

The project uses automated tests across multiple layers.

### Unit Testing

Individual components are tested independently, including:

* Password intelligence
* Attack engines
* Dictionary attacks
* Candidate pipelines
* Hash utilities
* Reporting components
* Application workflow

### Integration Testing

Multiple components are tested together to verify that data flows correctly between analysis, attack simulation, and reporting layers.

### End-to-End Testing

The end-to-end tests validate complete laboratory workflows from password analysis and candidate generation through attack simulation and report generation.

---

## Security Model

This project is designed around a **local, controlled laboratory model**.

It does not require:

* Real account credentials
* Live authentication services
* Unauthorized remote targets
* Credential harvesting
* Exploitation of third-party systems

The intended workflow is:

```text
Authorized Laboratory Input
          │
          ▼
   Password Analysis
          │
          ▼
      Hash Analysis
          │
          ▼
 Candidate Generation
          │
          ▼
 Attack Simulation
          │
          ▼
    Result Analysis
          │
          ▼
   Security Findings
          │
          ▼
    Audit Report
```

---

## Example Use Cases

The suite can be used for:

1. Password-policy validation in a laboratory environment
2. Educational demonstration of password attack concepts
3. Controlled dictionary-attack experiments
4. Brute-force search-space analysis
5. Password mutation research
6. Hash-format identification
7. Security-audit report generation
8. Automated regression testing of credential-security components

---

## Project Goals

The project focuses on combining several password-security assessment capabilities into one maintainable application.

Primary goals:

* Provide practical password-security analysis
* Demonstrate credential attack mechanics safely
* Automate repeatable laboratory assessments
* Produce structured security findings
* Maintain modular and testable code
* Support future expansion of attack and analysis modules

---

## Limitations

Cracking-time estimates and attack simulations are laboratory approximations.

Actual password-cracking performance depends on factors such as:

* Hardware
* Hashing algorithm
* Hash parameters
* Parallelization
* Candidate-generation strategy
* Password distribution
* Attack implementation

Therefore, results should be interpreted as security-assessment measurements rather than exact predictions of real-world attack duration.

---

## Responsible Use

Use this project only against:

* Your own test passwords
* Deliberately created laboratory credentials
* Systems you own
* Systems for which you have explicit authorization
* Controlled educational environments

Do not use the toolkit to obtain unauthorized access to accounts, systems, networks, or data.

---

## Project Status

**Current Version:** `0.2.0`

The current release contains the core password-analysis, hash-analysis, candidate-generation, attack-simulation, testing, and reporting infrastructure.

Future development can extend the suite with additional hash formats, configurable attack strategies, richer password intelligence, expanded reporting, and additional controlled laboratory scenarios.

---

## License

This repository is intended as an educational and authorized security-assessment project.

Use responsibly and only within environments where you have explicit authorization.

---

## Author

**Shaikh Shariq Ibrahim**

Cybersecurity / Computer Applications

GitHub:
https://github.com/Shaikhshariq-tech
