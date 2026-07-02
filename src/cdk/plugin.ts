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
 * both — and this package stays zero-dependency and version-agnostic. You only
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
   * advisory best-practice nudges, and a validation plugin fails `cdk synth` —
   * failing every build over advisory findings would train users to ignore the
   * tool. Opt into `'LOW'` explicitly to gate on everything.
   */
  readonly minimumSeverity?: Severity;
  /** Reported back to CDK for analytics; an arbitrary semver string. */
  readonly version?: string;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
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

    for (const templatePath of context.templatePaths) {
      let template: CfnTemplate;
      try {
        template = JSON.parse(
          readFileSync(templatePath, 'utf8')
        ) as CfnTemplate;
      } catch (error) {
        // CDK just wrote this template, so failing to read it means something
        // is genuinely wrong. Silently skipping would validate nothing and
        // still report success — fail loudly instead.
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
          severity: 'HIGH',
        });
        continue;
      }

      const findings = runRules(template, this.rules).filter(
        (finding) => SEVERITY_ORDER[finding.severity] >= threshold
      );

      for (const finding of findings) {
        const rule = rulesById.get(finding.ruleId);
        violations.push({
          ruleName: finding.ruleId,
          description: finding.issue,
          fix: finding.recommendation,
          severity: finding.severity,
          violatingResources: [
            {
              resourceLogicalId: finding.resourceId,
              templatePath,
              locations: [finding.resourceId],
            },
          ],
          ruleMetadata: rule
            ? {
                wafPillar: rule.metadata.wafPillar,
                awsDocUrl: rule.metadata.awsDocUrl,
              }
            : undefined,
        });
      }
    }

    return {
      violations,
      success: violations.length === 0,
      pluginVersion: this.version,
    };
  }
}
