import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eventbridgeTargetDlqMissing } from './eventbridgeTargetDlqMissing';

describe('eventbridge-target-dlq-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eventbridgeTargetDlqMissing]);

  const rule = (targets: object[]): CfnTemplate => ({
    Resources: {
      Rule: { Type: 'AWS::Events::Rule', Properties: { Targets: targets } },
    },
  });

  it('flags targets without a DLQ and counts them', () => {
    const findings = run(
      rule([
        { Id: 'a', Arn: 'arn:a' },
        { Id: 'b', Arn: 'arn:b', DeadLetterConfig: { Arn: 'arn:dlq' } },
      ])
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('1 target(s)');
  });

  it('does not flag rules whose targets all have DLQs, or with no targets', () => {
    expect(
      run(
        rule([{ Id: 'a', Arn: 'arn:a', DeadLetterConfig: { Arn: 'arn:dlq' } }])
      )
    ).toHaveLength(0);
    expect(run(rule([]))).toHaveLength(0);
  });
});
