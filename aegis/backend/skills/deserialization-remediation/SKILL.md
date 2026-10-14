---
name: deserialization-remediation
description: Plan unsafe-deserialization or unsafe object-loading mitigations when the advisory and selected source show that boundary.
---

Identify the supplied object-loading API, data source and required schema. Prefer an advisory-confirmed compatible upgrade when it closes the issue; source mitigation needs a demonstrated untrusted-data boundary.
Propose an existing safe data-only loader or validated schema supported by the packet. Safe mode can change accepted types and error behaviour; explicitly plan compatibility checks. Never imply a Python pickle or Java native-object loader becomes safe merely by validating a filename or adding generic input sanitisation.
Describe malicious-object rejection and expected benign-data regression cases without generating or executing an exploit. Request missing serializer, caller or schema context before selecting an API replacement.
