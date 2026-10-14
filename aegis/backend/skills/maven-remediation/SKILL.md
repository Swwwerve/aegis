---
name: maven-remediation
description: Plan fixes for affected Maven projects, including inherited parent/BOM versions and dependencyManagement ownership.
---

Find which supplied POM owns the affected dependency's effective version: explicit declaration, property, dependencyManagement, imported BOM or parent. A Spring Boot parent version is not every managed artifact's version.
Prefer the narrowest compatible confirmed fix. Propose updating the owning property/BOM/parent only when supplied effective-version evidence supports it; explain the wider managed-version impact. Avoid a child override that silently conflicts with platform management or a reactor-wide upgrade for one module without evidence.
For missing inherited/effective versions or unavailable artifacts, request resolved dependency-tree/parent context. Do not infer a clean graph from an offline cache failure.
Describe proposed Maven dependency-tree and module regression checks with supplied cwd and evidence. Builds, downloads, POM edits and tests are proposals only.
