# Changelog

All notable changes to this package are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-07-25

Consistency hardening from an external review of `0.5.0` (full framework + all
131 rules). Theme: the "unknown ≠ violation" doctrine was the norm but not
enforced — a minority of rules could flag values they cannot decide. All such
paths found are fixed, and a new contract test makes the doctrine mechanical.

### Changed — scan output may shift (fewer false positives)

- **30 rules no longer flag undecidable (intrinsic) or string-boolean values.**
  Three classes, all the same doctrine violation:
  - *Boolean deciders*: raw `=== true` comparisons (`dynamodb-pitr-disabled`,
    `apigateway-default-endpoint-enabled`) and flag-path
    `asBoolean(x) !== true` without an intrinsic guard
    (`ecs-deployment-circuit-breaker-disabled`,
    `eks-private-endpoint-access-disabled`, `elasticache-failover-disabled`,
    `elb-logging-disabled`, `elb-deletion-protection-disabled`,
    `msk-client-authentication-missing`, `msk-broker-logging-disabled`,
    `glue-connection-network-isolation`) — including intrinsic *container*
    blocks (`DeploymentConfiguration`, `LoggingInfo`, `ClientAuthentication`
    mechanism blocks, `LoadBalancerAttributes` and entries,
    `ConnectionProperties`, `PhysicalConnectionRequirements`, global-table
    replica entries), not just leaves.
  - *Policy condition values*: an intrinsic `aws:SecureTransport` value now
    counts as the benign TLS shape instead of a lockout/missing-TLS finding
    (`s3-bucket-policy-non-ssl` and the S3/SNS/SQS/KMS self-lockout rules,
    via the shared `isFalsyConditionValue` in `policy.ts`).
  - *List and wrapper deciders*: whole-list intrinsics no longer read as
    "empty/missing" and intrinsic config wrappers are no longer read through
    with `?.` — `cloudwatch-alarm-actions-missing`,
    `eks-public-endpoint-unrestricted`, `rds-logging-disabled`,
    `opensearch-access-control-weak`, `apigateway-stage-logging-disabled`,
    `apigateway-throttling-missing`, `s3-bucket-public-access`,
    `eks-secrets-encryption-disabled`, `eks-control-plane-logging-disabled`,
    `redshift-audit-logging-disabled`,
    `autoscaling-group-no-elb-healthcheck`,
    `acm-certificate-email-validation`, `dynamodb-autoscaling-missing`,
    `waf-web-acl-misconfigured`, `security-group-no-rules`.
- **`lambda-runtime-deprecated` skips CDK-internal helper functions**
  (log-retention, auto-delete-objects, AwsCustomResource singleton) — their
  runtime is pinned by the installed aws-cdk-lib and not actionable by the
  user, matching the other Lambda rules.
- **`lambda-env-sensitive-data` no longer flags pointer shapes**: literal ARNs,
  SSM parameter paths, `{{resolve:...}}` dynamic references, and keys that
  name a pointer (`SECRET_ARN`, `API_KEY_PARAMETER_NAME`) are the
  *recommended* remediation and are now skipped. URLs are deliberately still
  flagged (webhook and basic-auth URLs are themselves credentials), and
  `*_KEY_ID` keys (`ACCESS_KEY_ID`) are carved out of the pointer-suffix
  exemption. Real literal secrets still flag.
- **CDK plugin groups findings per rule+message** into one `PolicyViolation`
  with many `violatingResources` (CDK's native model), instead of one
  violation per resource.

### Added

- **Intrinsics contract test** (`src/intrinsics.contract.test.ts`): for every
  rule, the boolean-ish leaves that differ between its own `flagged`/`fixed`
  examples are replaced with `Fn::If` intrinsics in the fixed template, and
  the rule must stay silent. This is what surfaced the 9 extra rules above and
  prevents the class from regressing.
- **CDK plugin fails closed on a crashing rule**: a rule that throws now emits
  a `cdk-insights-rules/rule-execution-error` violation (mirroring the
  existing `unreadable-template` path) instead of a console warning and a
  passing build. Both plugin-internal violations use severity `error` — CDK's
  own formatter vocabulary — so they render red and sort first; catalog
  findings keep the catalog's severity taxonomy (surfaced by CDK as
  `customSeverity`).
- **CDK plugin propagates full rule metadata**: `remediationSteps` and
  `complianceFrameworks` now reach `ruleMetadata` alongside `wafPillar` and
  `awsDocUrl`.

### Fixed

- Documented that the plugin's `version` option is analytics-only
  (`pluginVersion`) and does not select a rule set.

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
