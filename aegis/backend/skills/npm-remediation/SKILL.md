---
name: npm-remediation
description: Plan npm, pnpm, Yarn or Bun dependency/API fixes for an affected Node project and its existing workspace lockfile.
---

Use packageManager and existing lockfile evidence to choose npm, pnpm, Yarn or Bun; do not replace the project's manager. Distinguish direct dependencies, transitive paths, npm aliases and workspace owners.
Prefer a compatible confirmed fixed dependency release. For a transitive finding, identify the owning direct dependency; do not recommend an override that lacks clear compatibility and ownership evidence unless compatibility and ownership are supported by the packet. Request missing graph evidence rather than guessing the parent.
Propose a targeted manifest update and lock regeneration with the existing manager. Note lifecycle scripts and cache/network prerequisites as implementation considerations; do not run them. Do not hand-edit integrity/resolution entries, delete the whole lockfile, or claim npm audit fix is a reviewed fix.
Check Node engine constraints and supplied affected API call sites. Propose the selected workspace's regression checks, with upgrade risks and evidence references.
