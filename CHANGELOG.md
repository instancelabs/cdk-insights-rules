# Changelog

All notable changes to this package are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-07-13

Five new rules closing the coverage gaps named in the 2026-07-13 external audit (131 rules total):

- **`imagebuilder-ami-public-launch-permission` (CRITICAL)** — an Image Builder distribution whose AMI launch permission includes the "all" user group shares the produced image with every AWS account. Handles both PascalCase and camelCase spellings of the user-authored configuration blob.
- **`s3-bucket-policy-public-read` (CRITICAL)** — a bucket policy that Allows object reads to a wildcard principal with no scoping condition. Complements the Block-Public-Access rule by flagging the explicit grant itself; CloudFront-OAC-scoped and org/account-scoped statements are not flagged.
- **`iam-role-anonymous-assume` (CRITICAL)** — a role trust policy assumable by a wildcard principal with no scoping condition: anyone with an AWS account can become the role. Closes the hole beside `iam-cross-account-trust`, which only parses literal account ids.
- **`secrets-manager-rotation-missing` (MEDIUM)** — a secret with no rotation schedule in the template (Security Hub SecretsManager.1). Stands down for the whole template when any rotation schedule's target is unresolvable, per the no-false-positives stance.
- **`rds-master-password-plaintext` (HIGH)** — a literal MasterUserPassword in the template. Dynamic references ('{{resolve:...}}') and intrinsics are fine; the companion to `ecs-secrets-plaintext`.

## [0.4.0] - 2026-07-13

Fixes from an independent three-lens audit (first-touch DX, AWS technical
correctness across 32 sampled rules, supply-chain trust). Full report themes:
one dead rule, two severity overclaims, count-narrative drift, and release
hardening.

### Changed — scan output may shift

- **`vpc-default-security-group-rules-present` rewritten — it could previously never fire.** It matched security groups named "default", but that name is reserved (EC2 rejects it) and the real default SG never appears as a template resource. It now detects standalone `AWS::EC2::SecurityGroupIngress`/`Egress` resources whose `GroupId` references `Fn::GetAtt [Vpc, DefaultSecurityGroup]` — the actual template-visible way rules get attached to a default group.
- **`s3-bucket-public-access` severity CRITICAL → MEDIUM, wording corrected.** Since April 2023 new buckets get Block Public Access by default; a bucket with no explicit configuration is protected by service defaults. The rule now frames explicit configuration as hardening (visible, portable protection) instead of claiming default buckets are "exposable".
- **`rds-encryption-disabled` severity CRITICAL → MEDIUM** (aligning with Security Hub/CIS — at-rest encryption is defense-in-depth, not a directly exploitable exposure) **and read replicas are now exempt**: they inherit `StorageEncrypted` from their source and cannot set it, so flagging them was un-fixable.
- **`lambda-memory-optimization` severity MEDIUM → LOW** — ">1024 MB" is frequently legitimate for CPU-bound functions; it now sits below clear-cut waste like gp2 volumes.
- **API Gateway ruleIds normalized to the `apigateway-` prefix**: `api-gateway-method-auth-missing` → `apigateway-method-auth-missing`, `api-gateway-logging-disabled` → `apigateway-stage-logging-disabled`. Suppressions written against the old ids keep working via the new `legacyRuleIds` mechanism.
- `lambda-runtime-deprecated` no longer flags `java11` — AWS has not announced a Lambda deprecation for it (Corretto 11 support runs to 2027).
- `dynamodb-encryption-aws-owned-key` description now matches what the check enforces (opting out of the AWS-owned default key), instead of overclaiming "customer-controlled" encryption.

### Added

- `legacyRuleIds` on rule metadata: renamed rules keep honoring suppressions written against their former ids, and the duplicate-id contract test covers aliases.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), linked from CONTRIBUTING.
- The security scan now covers **all of `src/**`** (engine, plugin, contract tests) with narrow, documented per-file exemptions — previously only `src/rules/**` was scanned.
- The release workflow now targets a `release` GitHub Environment, so npm publishing can be gated behind a required-reviewer approval, decoupling "merge to main" from "publish".

### Fixed

- Reconciled the rule-count narrative across README, CATALOG, the issue template, and NOTICE (which referenced files that don't exist). Hardcoded counts removed so they can't rot.

## [0.3.0] - 2026-07-02

Eight new rules closing the last parity gaps with the CDK Insights CLI's
native checks (126 rules total), plus one rule update:

### Added

- `s3-bucket-encryption-aws-managed` (MEDIUM) — no explicit BucketEncryption
  (SSE-S3 default applies; not customer-controlled)
- `eks-private-endpoint-access-disabled` (MEDIUM) — public API access without
  private endpoint access
- `eventbridge-rule-disabled` (MEDIUM, OpsEx) — rules with State DISABLED
- `ebs-volume-gp2-storage` (LOW, Cost) — gp2 where gp3 is cheaper
- `msk-data-volume-cmk-missing` (LOW) — broker volumes on the AWS-managed key
- `lambda-permission-scoped-wildcard` (LOW) — wildcard Principal scoped only
  by a source/org condition (org-shared layers exempt)
- `security-group-unrestricted-egress` (LOW) — advisory; allow-all outbound
  is the CDK default and is documented as such
- `security-group-no-rules` (LOW, OpsEx) — orphaned/empty security groups

### Changed

- `waf-webacl-misconfigured` now flags any rule-less WebACL (not only
  default-Allow ones) — a WebACL with no rules inspects nothing.

## [0.2.0] - 2026-07-02

The catalog release: **the bulk of CDK Insights' static detection rules are now
open source** — 118 rules (12 CRITICAL, 31 HIGH, 50 MEDIUM, 25 LOW) across five
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
