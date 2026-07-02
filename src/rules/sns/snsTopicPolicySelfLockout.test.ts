import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { snsTopicPolicySelfLockout } from './snsTopicPolicySelfLockout';

const topicPolicy = (statement: object): CfnTemplate => ({
  Resources: {
    Policy: {
      Type: 'AWS::SNS::TopicPolicy',
      Properties: {
        Topics: ['arn:aws:sns:eu-west-2:1:t'],
        PolicyDocument: { Version: '2012-10-17', Statement: [statement] },
      },
    },
  },
});

describe('sns-topic-policy-self-lockout', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [snsTopicPolicySelfLockout]);

  it('flags a blanket Deny on sns:*', () => {
    expect(
      run(
        topicPolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 'sns:*',
          Resource: '*',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag the TLS-enforcement Deny', () => {
    expect(
      run(
        topicPolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 'sns:*',
          Resource: '*',
          Condition: { Bool: { 'aws:SecureTransport': false } },
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag a Deny against a specific principal', () => {
    expect(
      run(
        topicPolicy({
          Effect: 'Deny',
          Principal: { AWS: 'arn:aws:iam::999988887777:root' },
          Action: 'sns:*',
          Resource: '*',
        })
      )
    ).toHaveLength(0);
  });
});
