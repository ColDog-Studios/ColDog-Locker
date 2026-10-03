# Project Context

This directory contains maintainer and agent *(clanker)*-facing context for ColDog Locker. It is intentionally separate from `docs/`, because the app's Help > Documentation links users to `docs/`.

## Contents

- [Architecture](architecture.md) - solution layout, dependency flow, lifecycle notes, and maintainer guidance.
- [GUI Status and Plans](gui-plans.md) - Avalonia, TUI, and GUI launcher status.
- [Distribution Plan](distribution-plan.md) - packaging direction, release scope, update behavior, and open distribution decisions.
- [Local Packaging](packaging.md) - local installer/package build commands and validation notes.
- [Release Automation](release-automation.md) - release workflow, version/tag policy, package build entrypoints, and validation checklist.
- [Public Launch Review](launch-review.md) - launch blockers, reproduced security and data-loss findings, code quality review, and release validation requirements at commit `9d1a618`.
- [Launch Remediation](launch-fixes.md) - implementation status and verification for every launch-review finding.
- [Performance Baselines](performance.md) - repeatable published-CLI workloads, measured timings, and profiling limitations.
- [Archive Protocol Review](archive-protocol-review.md) - version 2 format invariants, adversarial coverage, KDF measurements, and review limits.
