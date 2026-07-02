import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eventbridgeRuleNoTargets } from './eventbridgeRuleNoTargets';

describe('eventbridge-rule-no-targets', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eventbridgeRuleNoTargets]);

  const rule = (properties: object): CfnTemplate => ({
    Resources: {
      Rule: { Type: 'AWS::Events::Rule', Properties: properties },
    },
  });

  it('flags a rule with no targets (absent or empty)', () => {
    expect(run(rule({ ScheduleExpression: 'rate(5 minutes)' }))).toHaveLength(
      1
    );
    expect(
      run(rule({ ScheduleExpression: 'rate(5 minutes)', Targets: [] }))
    ).toHaveLength(1);
  });

  it('does not flag a rule with targets', () => {
    expect(run(rule({ Targets: [{ Id: 'w', Arn: 'arn:fn' }] }))).toHaveLength(
      0
    );
  });
});
