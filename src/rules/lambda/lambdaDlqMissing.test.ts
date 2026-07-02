import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaDlqMissing } from './lambdaDlqMissing';

describe('lambda-dlq-missing', () => {
  const run = (template: CfnTemplate) => runRules(template, [lambdaDlqMissing]);

  const fn = (properties: object = {}) => ({
    Type: 'AWS::Lambda::Function',
    Properties: properties,
  });

  it('flags an async-invoked function without a DLQ', () => {
    expect(
      run({
        Resources: {
          Fn: fn(),
          Perm: {
            Type: 'AWS::Lambda::Permission',
            Properties: {
              FunctionName: { Ref: 'Fn' },
              Principal: 'events.amazonaws.com',
              Action: 'lambda:InvokeFunction',
            },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('suggests an EventSourceMapping failure destination for poll-based sources', () => {
    const findings = run({
      Resources: {
        Fn: fn(),
        Esm: {
          Type: 'AWS::Lambda::EventSourceMapping',
          Properties: {
            FunctionName: { 'Fn::GetAtt': ['Fn', 'Arn'] },
            EventSourceArn: 'arn:aws:sqs:eu-west-2:1:q',
          },
        },
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('event source mapping');
  });

  it('does not flag DLQs, OnFailure destinations, sync-only, or unknown-mode functions', () => {
    expect(
      run({
        Resources: {
          Fn: fn({ DeadLetterConfig: { TargetArn: 'arn:sqs' } }),
          Perm: {
            Type: 'AWS::Lambda::Permission',
            Properties: {
              FunctionName: { Ref: 'Fn' },
              Principal: 'sns.amazonaws.com',
              Action: 'lambda:InvokeFunction',
            },
          },
        },
      })
    ).toHaveLength(0);
    expect(
      run({
        Resources: {
          Fn: fn(),
          Invoke: {
            Type: 'AWS::Lambda::EventInvokeConfig',
            Properties: {
              FunctionName: { Ref: 'Fn' },
              Qualifier: '$LATEST',
              DestinationConfig: {
                OnFailure: { Destination: 'arn:aws:sqs:eu-west-2:1:dlq' },
              },
            },
          },
        },
      })
    ).toHaveLength(0);
    // No invocation source in template: could be sync from another stack.
    expect(run({ Resources: { Fn: fn() } })).toHaveLength(0);
  });
});
