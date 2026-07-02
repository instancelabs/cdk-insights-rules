import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eventbridgeRuleDisabled } from './eventbridgeRuleDisabled';

describe('eventbridge-rule-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eventbridgeRuleDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::Events::Rule', Properties: { ...properties } },
    },
  });

  it('flags a disabled rule', () => {
    expect(run(res({ State: 'DISABLED' }))).toHaveLength(1);
  });

  it('does not flag enabled, default, or intrinsic states', () => {
    expect(run(res({ State: 'ENABLED' }))).toHaveLength(0);
    expect(run(res({}))).toHaveLength(0);
    expect(
      run(res({ State: { 'Fn::If': ['X', 'ENABLED', 'DISABLED'] } }))
    ).toHaveLength(0);
  });
});
