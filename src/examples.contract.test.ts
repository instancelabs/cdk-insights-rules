import { describe, expect, it } from 'vitest';
import { rules } from './registry';
import { runRules } from './runRules';
import { synthesizeExample } from './testutil/synthesizeExample';
import type { Rule } from './types';

/**
 * The guarantee behind every rule's before/after example: `flagged` MUST trip
 * the rule and `fixed` MUST NOT. This suite enforces it by actually running
 * each snippet - the code is executed inside a real CDK stack, synthesized
 * with aws-cdk-lib, and the resulting template is fed to the rule. An example
 * that drifts from the detection logic fails CI.
 */

const findingsOf = async (rule: Rule, snippet: string) =>
  runRules(await synthesizeExample(snippet), [rule], {
    onRuleError: (ruleId, error) => {
      throw new Error(`${ruleId} threw on its own example: ${error}`);
    },
  });

describe('example contract: flagged trips the rule, fixed does not', () => {
  for (const rule of rules) {
    describe(rule.metadata.ruleId, () => {
      it('example.flagged trips the rule', async () => {
        const findings = await findingsOf(rule, rule.example.flagged);
        expect(findings.length).toBeGreaterThan(0);
      }, 30_000);

      it('example.fixed does not trip the rule', async () => {
        const findings = await findingsOf(rule, rule.example.fixed);
        expect(findings).toHaveLength(0);
      }, 30_000);
    });
  }
});
