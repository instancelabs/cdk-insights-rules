import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudwatchLogsRetentionMissing } from './cloudwatchLogsRetentionMissing';

describe('cloudwatch-logs-retention-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudwatchLogsRetentionMissing]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::Logs::LogGroup', Properties: { ...properties } },
    },
  });

  it('flags a log group with no retention', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('does not flag configured retention (number or intrinsic)', () => {
    expect(run(res({ RetentionInDays: 90 }))).toHaveLength(0);
    expect(
      run(res({ RetentionInDays: { 'Fn::If': ['X', 90, 30] } }))
    ).toHaveLength(0);
  });
});
