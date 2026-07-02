import { rules as allRules } from './registry.js';
import type { CfnTemplate, Finding, ReportFinding, Rule } from './types.js';

export interface RunRulesOptions {
  /**
   * Called when a rule throws. The run always continues — a buggy rule must
   * never take down a scan — but a rule that crashed produced *no findings*,
   * and silently ignoring that would fail open. Defaults to a `console.warn`;
   * pass your own handler to collect errors, or `() => {}` to silence.
   */
  onRuleError?: (ruleId: string, error: unknown) => void;
}

const warnRuleError = (ruleId: string, error: unknown): void => {
  console.warn(
    `cdk-insights-rules: rule "${ruleId}" threw and was skipped — its findings are missing from this run.`,
    error
  );
};

/**
 * Rule ids suppressed on a resource via its metadata:
 *
 *   Metadata: { 'cdk-insights': { suppress: ['rule-id', ...] } }
 *
 * In CDK: `cfnResource.addMetadata('cdk-insights', { suppress: [...] })`.
 * This is the acknowledged-finding escape hatch — without one, a finding a
 * user disagrees with can never be made to go away, and they remove the tool
 * instead.
 */
const suppressedRuleIds = (
  template: CfnTemplate,
  resourceId: string
): string[] => {
  const metadata = template.Resources?.[resourceId]?.Metadata as
    | Record<string, unknown>
    | undefined;
  const suppress = (
    metadata?.['cdk-insights'] as Record<string, unknown> | undefined
  )?.suppress;
  return Array.isArray(suppress)
    ? suppress.filter((id): id is string => typeof id === 'string')
    : [];
};

/**
 * Run rules against a synthesized CloudFormation template and collect findings.
 *
 * @param template A parsed `cdk synth` template (or any CloudFormation JSON).
 * @param rules    The rules to run. Defaults to the full catalog.
 * @param options  `onRuleError` to observe rules that throw.
 *
 * Each rule runs in isolation: if one throws, it's reported via `onRuleError`
 * and skipped, and the rest still run — a single buggy rule can never take
 * down a scan. Findings suppressed on the resource (see `suppressedRuleIds`)
 * are dropped.
 */
export const runRules = (
  template: CfnTemplate,
  rules: Rule[] = allRules,
  options: RunRulesOptions = {}
): Finding[] => {
  const onRuleError = options.onRuleError ?? warnRuleError;
  const findings: Finding[] = [];

  for (const rule of rules) {
    const report: ReportFinding = (resourceId, detail) => {
      if (
        suppressedRuleIds(template, resourceId).includes(rule.metadata.ruleId)
      ) {
        return;
      }
      findings.push({
        resourceId,
        ruleId: rule.metadata.ruleId,
        issue: detail.issue,
        recommendation: detail.recommendation,
        severity: rule.metadata.severity,
        wafPillar: rule.metadata.wafPillar,
      });
    };

    try {
      rule.check(template, report);
    } catch (error) {
      onRuleError(rule.metadata.ruleId, error);
    }
  }

  return findings;
};
