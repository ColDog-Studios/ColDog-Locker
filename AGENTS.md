# Agent Guidance

Use `docs/` only for user-facing documentation. The app's Help > Documentation links users there, so avoid adding maintainer-only planning notes, migration notes, or packaging implementation details to `docs/`.

Use `.agents/` for project context that helps future coding agents and maintainers understand the repository. Start with `.agents/README.md`, then open the relevant topic file:

- `.agents/architecture.md`
- `.agents/gui-plans.md`
- `.agents/distribution-plan.md`
- `.agents/packaging.md`
- `.agents/release-automation.md`

When updating packaging, release automation, architecture notes, or GUI migration context, update the matching `.agents/` file instead of linking normal users to that directory from the public README.

