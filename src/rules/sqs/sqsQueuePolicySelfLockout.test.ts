import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { sqsQueuePolicySelfLockout } from './sqsQueuePolicySelfLockout';

const queuePolicy = (statement: object): CfnTemplate => ({
  Resources: {
    Policy: {
      Type: 'AWS::SQS::QueuePolicy',
      Properties: {
        Queues: ['https://sqs.eu-west-2.amazonaws.com/1/q'],
        PolicyDocument: { Version: '2012-10-17', Statement: [statement] },
      },
    },
  },
});

describe('sqs-queue-policy-self-lockout', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [sqsQueuePolicySelfLockout]);

  it('flags a blanket Deny on sqs:*', () => {
    expect(
      run(
        queuePolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 'sqs:*',
          Resource: '*',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag the enforceSSL TLS Deny (CDK enforceSSL: true)', () => {
    expect(
      run(
        queuePolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 'sqs:*',
          Resource: '*',
          Condition: { Bool: { 'aws:SecureTransport': 'false' } },
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag a Deny with a NotPrincipal carve-out', () => {
    expect(
      run(
        queuePolicy({
          Effect: 'Deny',
          NotPrincipal: { AWS: 'arn:aws:iam::111122223333:root' },
          Principal: '*',
          Action: 'sqs:*',
          Resource: '*',
        })
      )
    ).toHaveLength(0);
  });
});
