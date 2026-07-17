---
name: codeaegis
description: Protects the codebase by running real-time security verification on code changes. Use this skill whenever you write or modify code to verify there are no secrets, vulnerable dependencies, or insecure configurations.
---

# CodeAegis Security Scanner Skill

This skill allows you to run real-time security verification on code changes using the local `codeaegis` command-line scanner.

## Triggering

This skill is automatically activated when you write or modify code files (such as Rust, Python, JavaScript, Terraform, etc.). You should use the `codeaegis` binary to scan any code you produce.

## Commands and Usage

You can run the following shell commands in the project directory:

### 1. Scan a specific file or directory
```bash
codeaegis scan <PATH>
```

Example:
```bash
codeaegis scan ./src/main.rs
```

### 2. Scan the entire workspace
```bash
codeaegis scan .
```

### 3. Scan and generate a security report
To generate a SARIF report of findings:
```bash
codeaegis scan . --report report.sarif
```

## How to Handle Scan Results

- **Risk Tier: None**: The code is safe to propose or apply.
- **Risk Tier: Low / Medium / High / Critical**:
  1. Review the printed findings and the summary provided by the CodeAegis Critic (LLM Judge).
  2. Fix the issues identified (e.g. remove hardcoded secrets, update insecure dependencies, or fix IaC misconfigurations).
  3. Re-run `codeaegis scan` to confirm the code is clean before presenting it to the user.
