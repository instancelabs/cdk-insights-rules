# Changelog

All notable changes to this package are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-02

The catalog release: **all of CDK Insights' static detection rules are now open
source** — 118 rules (12 CRITICAL, 31 HIGH, 50 MEDIUM, 25 LOW) across five
Well-Architected pillars, up from 9.

### Added

- **109 rules** ported from the CDK Insights product: Security (76),
  Reliability (15), Cost Optimization (9), Operational Excellence (10),
  Performance Efficiency (1) — see [CATALOG.md](CATALOG.md).
- **Example synthesis contract**: every rule's before/after CDK example is
  synthesized with real `aws-cdk-lib` in CI and proven to trip / not trip the
  rule — examples can never drift from detection logic.
- **CDK policy-validation plugin** (`@instance-labs/cdk-insights-rules/cdk`) —
  `CdkInsightsRulesPlugin` for `Validations.of(app).addPlugins(...)`; runs the
  rules on every `cdk synth`. Defaults to `minimumSeverity: 'MEDIUM'` and fails
  loudly on unreadable templates.
- **Suppressions**: acknowledge a finding per resource via
  `Metadata: { 'cdk-insights': { suppress: ['rule-id'] } }`.
- **Engine observability**: `runRules` accepts `onRuleError` (default warns) —
  a crashing rule can never silently fail open.
- **Shared helpers** for rule authors: `isIntrinsic`, `asBoolean`,
  `isCdkInternalLogicalId` (`cfn.ts`) and IAM-policy-document helpers
  (`policy.ts`), all exported.
- **Individual rule exports** for cherry-picking and tree-shaking
  (`"sideEffects": false`).
- **`defineRule`** authoring helper for type-checked rule literals.

### Changed

- False-positive discipline throughout: intrinsic (`Ref`/`Fn::If`) values are
  never flagged, CloudFormation string-booleans (`"true"`) are normalized,
  CDK-internal helper resources (log-retention handlers, custom-resource
  providers) are exempt from advisory Lambda rules, and the TLS-enforcement
  Deny that CDK's `enforceSSL` emits is exempt from all self-lockout rules.

## [0.1.0]

- Initial catalog: 9 rules across 7 services, a pure `runRules` engine, a rule
  contract, a contract test, and CI (security scan + tests + AI review).
