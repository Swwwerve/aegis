---
name: regression-testing
description: Plan focused regression validation when the packet contains associated tests or declared project test commands.
---

Use the affected API's demonstrated boundary to propose a reproducer that fails for the original behaviour and passes for the proposed change, alongside a benign-behaviour case. Do not substitute a package-version assertion for a behaviour test when the vulnerability depends on application logic.
Reference supplied related tests as candidates until their imports and assertions establish relevance. Describe additions to existing supplied test files; request context before selecting an unseen fixture or new test path.
Propose the smallest applicable test command and any justified wider checks using known cwd/runtime prerequisites. Do not execute checks, fabricate output, or mark validation passed. Describe what a future executor must observe to accept the fix.
