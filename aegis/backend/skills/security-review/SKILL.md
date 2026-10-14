---
name: security-review
description: Plan security validation for source/configuration mitigations involving trust boundaries, injection, deserialization, SSRF, traversal or access-control bypass.
---

Review the proposed source/configuration boundary using supplied evidence. Describe how the mitigation closes the advisory condition, preserves required functionality, and avoids adjacent bypasses. Do not equate sanitisation with safety or package call counts with exploitation.
For a package-only fix, use this skill only if application-level boundary validation is also necessary. Limit proposed adversarial cases to the described CVE and the selected caller; do not expand into a repository-wide audit.
Identify residual risk and required evidence, including external/runtime assumptions the packet cannot prove. State review criteria as future checks, never approval of an unexecuted fix.
