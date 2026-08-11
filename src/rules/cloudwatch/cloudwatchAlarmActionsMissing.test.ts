import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudwatchAlarmActionsMissing } from './cloudwatchAlarmActionsMissing';

describe('cloudwatch-alarm-actions-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudwatchAlarmActionsMissing]);

  const res = (
    properties: object,
    type = 'AWS::CloudWatch::Alarm'
  ): CfnTemplate => ({
    Resources: {
      R: { Type: type, Properties: { ...properties } },
    },
  });

  it('flags missing actions and missing-data handling (two findings)', () => {
    expect(run(res({}))).toHaveLength(2);
  });

  it('skips intrinsic AlarmActions instead of flagging it', () => {
    expect(
      run(
        res({
          AlarmActions: { 'Fn::If': ['Prod', ['arn:sns'], []] },
          TreatMissingData: 'notBreaching',
        })
      )
    ).toHaveLength(0);
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

  it('applies the same action and missing-data checks to log alarms', () => {
    expect(run(res({}, 'AWS::CloudWatch::LogAlarm'))).toHaveLength(2);
    expect(
      run(
        res(
          {
            AlarmActions: ['arn:aws:sns:eu-west-2:111122223333:oncall'],
            TreatMissingData: 'notBreaching',
          },
          'AWS::CloudWatch::LogAlarm'
        )
      )
    ).toHaveLength(0);
  });
});
