---
name: python-remediation
description: Plan a PyPI dependency or affected Python API change using manifest pins, lock evidence, runtime constraints and caller snippets.
---

Identify the owning pyproject.toml, requirements file, setup metadata, or Pipfile from supplied paths. A manifest constraint is not an observed installation; keep pinned and resolved versions distinct.
For a confirmed dependency fix, propose the smallest supported constraint change and regeneration of the existing uv/Poetry/pipenv lock using that project's manager. Do not hand-edit transitive lock entries or introduce a different manager. Check requires-python and supplied API callers for compatibility; do not assume a fixed release supports the current interpreter.
For an API mitigation, scope the proposed change to the affected call and its input/output contract. Preserve exception handling and benign behaviour; missing caller context is a question, not permission to invent code.
Propose focused regression checks using supplied test commands and files. Installing, editing and running checks are future actions only.
