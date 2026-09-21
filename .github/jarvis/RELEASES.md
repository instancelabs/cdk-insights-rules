# Jarvis releases

Routine genuine Dependabot development-tool updates and bounded development-only lockfile patches merge without human review after current-head CI and branch rules pass. Runtime, major and other changes are held with a specific reason.

An authenticated owner request can release compatible dependency upgrades and Jarvis source repairs. Explicit “I reviewed this PR, merge and deploy” approval can release another same-repository PR, including human-authored work. The request pins the approved commit; changed code invalidates it. Broad requests to handle updates do not imply that Lee reviewed an arbitrary PR. All modes keep trusted current-head CI, current-main ancestry, hold labels, exact merge verification, and GitHub protections.

Deployment adapters use the same verified merged commit in development then production, with health checks and actual-outcome notifications. A merge-only package retains its existing publication process. Pending CI is checked with a bounded wait; failure or timeout never bypasses the gates.
