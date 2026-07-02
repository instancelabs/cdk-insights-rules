# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately via
[GitHub's private vulnerability reporting](https://github.com/instancelabs/cdk-insights-rules/security/advisories/new)
("Report a vulnerability" on the repository's Security tab). You'll get an
acknowledgement within 72 hours and a status update within 7 days.

In scope for this package:

- A way for a contributed rule to execute code or reach the network/filesystem
  despite the security scan (`scripts/security-scan.mjs`) and review process.
- A malicious-template input that makes the engine (`runRules`) or the CDK
  plugin execute code, hang, or otherwise misbehave beyond producing findings.
- Supply-chain issues in the release workflow (npm trusted publishing, OIDC).

Not in scope: a rule failing to detect a misconfiguration (that's a normal
bug — please open an issue), or vulnerabilities in the private CDK Insights
product (report those to the address on [cdkinsights.dev](https://cdkinsights.dev)).

## Supported versions

Only the latest published version of `@instance-labs/cdk-insights-rules`
receives security fixes.
