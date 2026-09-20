# Jarvis maintenance

Bounded automatic updates for existing stable, same-major development tools. The trusted workflow verifies the exact commit, required CI, current main and branch protections. Runtime dependencies, major upgrades, infrastructure packages and changed scripts are held for review. The only automatic repair restores otherwise unchanged npm lockfile metadata; it requires fresh CI.

This library/tool has no AWS development/production service. Verified development-tool updates may merge; package publication retains the existing explicit release/tag process.

Set repository variable `JARVIS_AUTO_MAINTENANCE` to `paused` or label a PR `jarvis-hold` to stop automation. Lee receives verified outcomes through the private Jarvis chat. No LLM calls are made by these workflows.
