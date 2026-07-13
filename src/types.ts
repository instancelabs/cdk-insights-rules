/**
 * The rule contract for CDK Insights.
 *
 * A rule is data + a pure function. It inspects a synthesized CloudFormation
 * template and reports a finding whenever it spots a misconfiguration. That's
 * the whole surface — no I/O, no network, no CDK, no filesystem. If you can
 * decide it from the template, you can write a rule for it.
 */

/** Finding severity, highest to lowest impact. */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/** The AWS Well-Architected pillar a rule maps to. Exactly one. */
export type WafPillar =
  | 'Security'
  | 'Reliability'
  | 'Cost Optimization'
  | 'Performance Efficiency'
  | 'Operational Excellence';

/** A single resource in a CloudFormation template. */
export interface CfnResource {
  /** e.g. "AWS::S3::Bucket" */
  Type: string;
  /**
   * Resource properties. Intentionally loose (`any`) so rules can read any
   * property without wrestling the type system — you are inspecting arbitrary
   * synthesized templates, so always guard your access (`?.`).
   */
  // biome-ignore lint/suspicious/noExplicitAny: templates are arbitrary JSON
  Properties?: Record<string, any>;
  [key: string]: unknown;
}

/** A synthesized CloudFormation template (the output of `cdk synth`). */
export interface CfnTemplate {
  Resources?: Record<string, CfnResource>;
  [key: string]: unknown;
}

/** What a rule emits, after the runner stamps on the rule's identity. */
export interface Finding {
  /** The logical id of the offending resource. */
  resourceId: string;
  /** The rule that produced this finding. */
  ruleId: string;
  /** What's wrong, in one sentence. */
  issue: string;
  /** How to fix it, in one sentence. */
  recommendation: string;
  severity: Severity;
  wafPillar: WafPillar;
}

/**
 * The reporter a rule is handed to flag a finding. Severity, pillar and ruleId
 * come from the rule's metadata — you only describe *what* is wrong and *how* to
 * fix it, for a specific resource. It's injected into every check so rules never
 * construct findings themselves.
 */
export type ReportFinding = (
  resourceId: string,
  detail: { issue: string; recommendation: string }
) => void;

/**
 * A rule's detection logic: look at the template, call `report(...)` for every
 * resource that violates the rule. Must be pure and deterministic.
 */
export type RuleCheck = (template: CfnTemplate, report: ReportFinding) => void;

/** Everything about a rule except its detection logic and example. */
export interface RuleMetadata {
  /** Stable, unique, kebab-case, e.g. "s3-bucket-versioning-disabled". */
  ruleId: string;
  /**
   * Former ruleIds this rule was published under. Suppressions written
   * against a legacy id keep working — the runner consults these too.
   */
  legacyRuleIds?: string[];
  /** Human-readable name, e.g. "S3 Bucket Versioning Disabled". */
  name: string;
  /** One sentence: what this rule detects. */
  description: string;
  severity: Severity;
  wafPillar: WafPillar;
  /** The CloudFormation resource type(s) this rule inspects. */
  resourceTypes: string[];
  /** A link to the authoritative AWS documentation for the control. */
  awsDocUrl: string;
  /** One or more concrete remediation steps. */
  remediationSteps: string[];
  /** Optional: compliance frameworks this control maps to. */
  complianceFrameworks?: string[];
}

/**
 * A before/after CDK snippet. `flagged` MUST trip the rule; `fixed` MUST NOT.
 * Both are validated in CI, so they can never drift from the detection logic.
 */
export interface RuleExample {
  flagged: string;
  fixed: string;
}

/** A complete rule: metadata + detection logic + a worked example. */
export interface Rule {
  metadata: RuleMetadata;
  check: RuleCheck;
  example: RuleExample;
}
