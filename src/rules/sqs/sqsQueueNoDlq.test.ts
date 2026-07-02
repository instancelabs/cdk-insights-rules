import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { sqsQueueNoDlq } from './sqsQueueNoDlq';

describe('sqs-queue-no-dlq', () => {
  const run = (template: CfnTemplate) => runRules(template, [sqsQueueNoDlq]);

  it('flags a queue with no DLQ but not the DLQ itself nor the producer', () => {
    const template = {
      Resources: {
        Main: { Type: 'AWS::SQS::Queue', Properties: {} },
        Dlq: { Type: 'AWS::SQS::Queue', Properties: {} },
        Producer: {
          Type: 'AWS::SQS::Queue',
          Properties: {
            RedrivePolicy: {
              deadLetterTargetArn: { 'Fn::GetAtt': ['Dlq', 'Arn'] },
            },
          },
        },
      },
    };

    const findings = run(template);

    expect(
      findings
        .filter((finding) => finding.resourceId === 'Main')
        .map((finding) => finding.ruleId)
    ).toContain('sqs-queue-no-dlq');
    expect(
      findings.filter((finding) => finding.resourceId === 'Dlq')
    ).toHaveLength(0);
    expect(
      findings.filter((finding) => finding.resourceId === 'Producer')
    ).toHaveLength(0);
  });

  it('does not flag a queue that has its own RedrivePolicy', () => {
    const findings = run({
      Resources: {
        Queue: {
          Type: 'AWS::SQS::Queue',
          Properties: {
            RedrivePolicy: {
              deadLetterTargetArn: { Ref: 'SomeOtherQueue' },
            },
          },
        },
      },
    });

    expect(
      findings.filter((finding) => finding.resourceId === 'Queue')
    ).toHaveLength(0);
  });
});
