# Changelog

All notable changes to this package are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CDK policy-validation plugin** (`@instance-labs/cdk-insights-rules/cdk`) —
  `CdkInsightsRulesPlugin`. Drop it into a CDK app via
  `Validations.of(app).addPlugins(...)` and every `cdk synth` runs the rules
  against the synthesized templates, failing synth on violations. Shapes are
  declared structurally, so the package stays zero-dependency and works with any
  `aws-cdk-lib` version.
- **Individual rule exports** from the package root, so consumers can cherry-pick
  and tree-shake (`import { lambdaUrlAuthNone } from '@instance-labs/cdk-insights-rules'`).
- **`defineRule`** authoring helper for type-checked rule literals.

## [0.1.0]

- Initial catalog: 9 rules across 7 services, a pure `runRules` engine, a rule
  contract, a contract test, and CI (security scan + tests + AI review).
