---
name: injection-remediation
description: Plan source-level injection mitigations when advisory and selected caller evidence show an unsafe interpreter or query boundary.
---

Follow the supplied input-to-sink path and identify whether the relevant boundary is SQL, NoSQL, shell, template or browser output. If a compatible dependency upgrade fully addresses the advisory, prefer that plan; load this skill only for necessary application changes.
Propose parameterisation or structured APIs at query boundaries, argv separation for processes, or context-specific output encoding for browser rendering as supported by the actual sink. An allowlist/escaping operation is not a universal substitute for parameterisation; do not invent a sanitizer API.
Preserve intended operators and trusted-input behaviour. Specify a focused regression case proving untrusted input cannot change syntax plus a benign input case. Request missing upstream validation or sink context. Nothing is executed.
