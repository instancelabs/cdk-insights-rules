import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudwatchLogAlarmNotificationDataExposure } from './cloudwatchLogAlarmNotificationDataExposure';

describe('cloudwatch-log-alarm-notification-data-exposure', () => {
  const run = (
    actionLogLineCount: unknown,
    extraProperties: Record<string, unknown> = {
      AlarmActions: ['arn:aws:sns:eu-west-2:111122223333:oncall'],
    },
    extraResources: CfnTemplate['Resources'] = {}
  ) =>
    runRules(
      {
        Resources: {
          ...extraResources,
          Alarm: {
            Type: 'AWS::CloudWatch::LogAlarm',
            Properties: {
              ActionLogLineCount: actionLogLineCount,
              ...extraProperties,
            },
          },
        },
      } satisfies CfnTemplate,
      [cloudwatchLogAlarmNotificationDataExposure]
    );

  it.each([1, 25, 50, '10'])('flags a positive literal count (%s)', (count) => {
    const findings = run(count);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.issue).toContain(String(Number(count)));
  });

  it.each([undefined, 0, '0'])(
    'does not flag disabled or omitted count (%s)',
    (count) => {
      expect(run(count)).toHaveLength(0);
    }
  );

  it('skips an intrinsic count because the resolved value is unknown', () => {
    expect(run({ Ref: 'LogLineCount' })).toHaveLength(0);
  });

  it('recognizes a CDK-style Ref to an SNS topic', () => {
    expect(
      run(
        10,
        { AlarmActions: [{ Ref: 'Topic' }] },
        { Topic: { Type: 'AWS::SNS::Topic' } }
      )
    ).toHaveLength(1);
  });

  it('recognizes SNS actions on other state transitions', () => {
    expect(
      run(10, {
        OKActions: ['arn:aws:sns:eu-west-2:111122223333:recovery'],
      })
    ).toHaveLength(1);
  });

  it('does not flag Lambda-only actions because AWS omits log lines from them', () => {
    expect(
      run(10, {
        AlarmActions: [
          'arn:aws:lambda:eu-west-2:111122223333:function:handle-alarm',
        ],
      })
    ).toHaveLength(0);
  });

  it.each([false, 'false'])(
    'does not flag when actions are disabled (%s)',
    (disabled) => {
      expect(
        run(10, {
          ActionsEnabled: disabled,
          AlarmActions: ['arn:aws:sns:eu-west-2:111122223333:oncall'],
        })
      ).toHaveLength(0);
    }
  );

  it('skips an unresolved ActionsEnabled value', () => {
    expect(
      run(10, {
        ActionsEnabled: { Ref: 'ActionsEnabled' },
        AlarmActions: ['arn:aws:sns:eu-west-2:111122223333:oncall'],
      })
    ).toHaveLength(0);
  });

  it('ignores unrelated resource types', () => {
    const template: CfnTemplate = {
      Resources: {
        Alarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: { ActionLogLineCount: 10 },
        },
      },
    };
    expect(
      runRules(template, [cloudwatchLogAlarmNotificationDataExposure])
    ).toHaveLength(0);
  });
});
