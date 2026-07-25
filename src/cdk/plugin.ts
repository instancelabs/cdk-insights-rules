import { readFileSync } from 'node:fs';
import { rules as allRules } from '../registry.js';
import { runRules } from '../runRules.js';
import type { CfnTemplate, Rule, Severity } from '../types.js';

/**
 * A drop-in CDK policy-validation plugin. Add it to your app and every
 * `cdk synth` runs the rules against the synthesized templates:
 *
 *   import { App, Validations } from 'aws-cdk-lib';
 *   import { CdkInsightsRulesPlugin } from '@instance-labs/cdk-insights-rules/cdk';
 *
 *   const app = new App();
 *   // ...define your stacks...
 *   Validations.of(app).addPlugins(
 *     new CdkInsightsRulesPlugin({ minimumSeverity: 'HIGH' }),
 *   );
 *
 * The plugin's shapes are declared locally (below) rather than imported from
 * aws-cdk-lib. CDK's `IPolicyValidationPluginBeta1` and the graduated
 * `IPolicyValidationPlugin` are structurally identical, so one class satisfies
 * both - and this package stays zero-dependency and version-agnostic. You only
 * need aws-cdk-lib in your own project to call `Validations.of(app)`.
 */

/** A resource that violated a rule (matches CDK's PolicyViolatingResource). */
export interface PolicyViolatingResource {
  readonly resourceLogicalId: string;
  readonly locations: string[];
  readonly templatePath: string;
}

/** A single violation (matches CDK's PolicyViolation). */
export interface PolicyViolation {
  readonly ruleName: string;
  readonly description: string;
  readonly violatingResources: PolicyViolatingResource[];
  readonly fix?: string;
  readonly severity?: string;
  readonly ruleMetadata?: { readonly [key: string]: string };
}

/** The report CDK expects back from `validate`. */
export interface PolicyValidationPluginReport {
  readonly violations: PolicyViolation[];
  readonly success: boolean;
  readonly pluginVersion?: string;
}

/** The context CDK passes to `validate` (paths to synthesized templates). */
export interface PolicyValidationContext {
  readonly templatePaths: string[];
}

export interface CdkInsightsRulesPluginOptions {
  /** Which rules to run. Defaults to the full catalog. */
  readonly rules?: Rule[];
  /**
   * Drop violations below this severity. Defaults to MEDIUM: LOW rules are
   * advisory best-practice nudges, and a validation plugin fails `cdk synth` -
   * failing every build over advisory findings would train users to ignore the
   * tool. Opt into `'LOW'` explicitly to gate on everything.
   */
  readonly minimumSeverity?: Severity;
  /**
   * Reported back to CDK for analytics as `pluginVersion`; an arbitrary
   * semver string. It does NOT select a rule set - the catalog is whatever
   * this installed package version ships (or the `rules` option).
   */
  readonly version?: string;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

/**
 * Everything the catalog knows about a rule, flattened into CDK's
 * string-to-string ruleMetadata shape so reports carry the full picture -
 * not just the pillar and doc link.
 */
const ruleMetadataOf = (rule: Rule): { [key: string]: string } => {
  const metadata: { [key: string]: string } = {
    wafPillar: rule.metadata.wafPillar,
    awsDocUrl: rule.metadata.awsDocUrl,
    remediationSteps: rule.metadata.remediationSteps.join(' | '),
  };
  if (rule.metadata.complianceFrameworks?.length) {
    metadata.complianceFrameworks =
      rule.metadata.complianceFrameworks.join(', ');
  }
  return metadata;
};

export class CdkInsightsRulesPlugin {
  public readonly name = 'cdk-insights-rules';
  public readonly ruleIds: string[];
  private readonly rules: Rule[];
  private readonly minimumSeverity: Severity;
  private readonly version?: string;

  constructor(options: CdkInsightsRulesPluginOptions = {}) {
    this.rules = options.rules ?? allRules;
    this.minimumSeverity = options.minimumSeverity ?? 'MEDIUM';
    this.version = options.version;
    this.ruleIds = this.rules.map((rule) => rule.metadata.ruleId);
  }

  validate(context: PolicyValidationContext): PolicyValidationPluginReport {
    const threshold = SEVERITY_ORDER[this.minimumSeverity];
    const violations: PolicyViolation[] = [];
    const rulesById = new Map(
      this.rules.map((rule) => [rule.metadata.ruleId, rule])
    );
    // CDK's model is one violation → many violatingResources; a rule tripping
    // on 20 resources should be one grouped entry, not 20. Findings with the
    // same rule and message merge across resources (and templates).
    const grouped = new Map<
      string,
      {
        ruleId: string;
        issue: string;
        recommendation: string;
        severity: Severity;
        resources: PolicyViolatingResource[];
      }
    >();
    // A rule that throws produced no findings - silently passing that check
    // would fail open, the dangerous direction in a synth gate.
    const crashed = new Map<
      string,
      { error: unknown; templatePaths: string[] }
    >();

    for (const templatePath of context.templatePaths) {
      let template: CfnTemplate;
      try {
        template = JSON.parse(
          readFileSync(templatePath, 'utf8')
        ) as CfnTemplate;
      } catch (error) {
        // CDK just wrote this template, so failing to read it means something
        // is genuinely wrong. Silently skipping would validate nothing and
        // still report success - fail loudly instead.
        violations.push({
          ruleName: 'cdk-insights-rules/unreadable-template',
          description: `Could not read or parse the synthesized template, so no rules were run against it: ${
            error instanceof Error ? error.message : String(error)
          }`,
          violatingResources: [
            {
              resourceLogicalId: '(template)',
              templatePath,
              locations: [templatePath],
            },
          ],
          // CDK's report formatter recognizes fatal|error|warning|info;
          // 'error' renders red and sorts first. Catalog findings keep the
          // catalog's own severity taxonomy (surfaced as customSeverity).
          severity: 'error',
        });
        continue;
      }

      const findings = runRules(template, this.rules, {
        onRuleError: (ruleId, error) => {
          const entry = crashed.get(ruleId) ?? { error, templatePaths: [] };
          entry.templatePaths.push(templatePath);
          crashed.set(ruleId, entry);
        },
      }).filter((finding) => SEVERITY_ORDER[finding.severity] >= threshold);

      for (const finding of findings) {
        // JSON encoding keeps the key collision-proof without embedding
        // control characters in source (a raw separator byte would make this
        // file binary to git and unreviewable in a PR).
        const key = JSON.stringify([
          finding.ruleId,
          finding.issue,
          finding.recommendation,
        ]);
        const entry = grouped.get(key) ?? {
          ruleId: finding.ruleId,
          issue: finding.issue,
          recommendation: finding.recommendation,
          severity: finding.severity,
          resources: [],
        };
        entry.resources.push({
          resourceLogicalId: finding.resourceId,
          templatePath,
          locations: [finding.resourceId],
        });
        grouped.set(key, entry);
      }
    }

    for (const entry of grouped.values()) {
      const rule = rulesById.get(entry.ruleId);
      violations.push({
        ruleName: entry.ruleId,
        description: entry.issue,
        fix: entry.recommendation,
        severity: entry.severity,
        violatingResources: entry.resources,
        ruleMetadata: rule ? ruleMetadataOf(rule) : undefined,
      });
    }

    for (const [ruleId, { error, templatePaths }] of crashed) {
      violations.push({
        ruleName: 'cdk-insights-rules/rule-execution-error',
        description: `Rule "${ruleId}" threw and was skipped - its checks did not run, so this report may be incomplete: ${
          error instanceof Error ? error.message : String(error)
        }`,
        violatingResources: templatePaths.map((templatePath) => ({
          resourceLogicalId: '(template)',
          templatePath,
          locations: [templatePath],
        })),
        severity: 'error',
      });
    }

    return {
      violations,
      success: violations.length === 0,
      pluginVersion: this.version,
    };
  }
}
