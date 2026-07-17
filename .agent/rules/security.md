# CodeAegis Security Verification Rule

This repository uses **CodeAegis** to ensure code changes are secure, free of secrets, dependency vulnerabilities, and insecure configurations.

## Instructions for AI Agents:
1. Whenever you modify or write code in this repository, you **MUST** run the local `codeaegis scan` CLI command to check your changes.
2. Do not commit or present code with high or critical vulnerabilities to the user.
3. Review the findings and their context-aware remediation hints to resolve any issues.
4. You can find detailed usage and CLI options in the Workspace Agent Skill definition at `.agent/skills/codeaegis/SKILL.md`.
