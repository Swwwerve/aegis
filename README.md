# aegis
Open Source Vulnerability Remediation Service

Give the system an open-source GitHub repository. It discovers vulnerable dependencies, determines which vulnerabilities actually matter, gathers only the relevant code/context, proposes a remediation, modifies the repository inside a sandbox, runs the tests, independently verifies the fix, and produces a PR-ready patch with an evidence-backed security report.

Traditional SCA tools tell developers what dependency to update. Our service autonomously determines whether a vulnerability affects the application, performs the upgrade, repairs resulting application-level breakages, generates regression/security tests, executes the application in an isolated sandbox, and provides evidence that the remediation actually works.
