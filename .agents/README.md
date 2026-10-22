# Project Context

This directory contains maintainer and agent-facing context for ColDog Locker. It is intentionally separate from `docs/`, because the app's Help > Documentation links users to `docs/`.

## Contents

- [Architecture](architecture.md) - solution layout, dependency flow, lifecycle notes, and maintainer guidance.
- [Interface Guidance](gui-plans.md) - GUI/CLI capability map, interaction, background work and native UX validation.
- [Packaging and Distribution](packaging.md) - local installer/package build commands and validation notes.
- [Release Automation](release-automation.md) - release workflow, version/tag policy, package build entrypoints, and validation checklist.
- [Performance Baselines](performance.md) - repeatable published-CLI workloads, measured timings, and profiling limitations.
- [Archive Protocol Review](archive-protocol-review.md) - version 2 format invariants, adversarial coverage, KDF measurements, and review limits.

Keep current behavior here, not chronological work logs. Git history preserves superseded plans and remediation checkpoints. Retain protocol invariants, reproducible test/benchmark evidence, current validation limits and commands that another maintainer can actually use. Build outputs, screenshots, temporary reports, logs and local credentials belong in ignored locations.
