import { rules as allRules } from './registry.js';
import type { CfnTemplate, Finding, ReportFinding, Rule } from './types.js';

/**
 * Run rules against a synthesized CloudFormation template and collect findings.
 *
 * @param template A parsed `cdk synth` template (or any CloudFormation JSON).
 * @param rules    The rules to run. Defaults to the full catalog.
 *
 * Each rule runs in isolation: if one throws, it's skipped and the rest still
 * run, so a single buggy rule can never take down a scan.
 */
export const runRules = (
  template: CfnTemplate,
  rules: Rule[] = allRules
): Finding[] => {
  const findings: Finding[] = [];

  for (const rule of rules) {
    const report: ReportFinding = (resourceId, detail) => {
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
    } catch {
      // A rule must never break the run. Detection bugs are surfaced by the
      // rule's own tests, not by crashing every other rule.
    }
  }

  return findings;
};
