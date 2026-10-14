---
name: gradle-remediation
description: Plan fixes for Gradle or Gradle Kotlin DSL projects using catalog, platform, constraint and resolved dependency evidence.
---

Identify the owning build file, version catalog, platform/BOM or constraint from supplied evidence. Dynamic Gradle expressions and declared ranges are not resolved versions.
Choose a targeted compatible confirmed version change at the correct owner; describe catalog/platform consumers affected by a shared change. Do not invent a catalog alias, force a transitive dependency without graph evidence, or replace Gradle with Maven.
Propose lock regeneration and dependencyInsight/test tasks only where the selected project and toolchain evidence supports them. Cache misses and wrapper download requirements are prerequisites, not proof of a successful check.
Request missing resolved graph or caller evidence. All edits and commands remain future plan steps.
