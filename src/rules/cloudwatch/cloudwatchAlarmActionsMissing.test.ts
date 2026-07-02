import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudwatchAlarmActionsMissing } from './cloudwatchAlarmActionsMissing';

describe('cloudwatch-alarm-actions-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudwatchAlarmActionsMissing]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::CloudWatch::Alarm', Properties: { ...properties } },
    },
  });

  it('flags missing actions and missing-data handling (two findings)', () => {
    expect(run(res({}))).toHaveLength(2);
  });

  it('does not flag a fully configured alarm', () => {
    expect(
      run(
        res({
          AlarmActions: ['arn:sns'],
          TreatMissingData: 'notBreaching',
        })
      )
    ).toHaveLength(0);
  });
});
