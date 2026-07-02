import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { kmsKeyPolicySelfLockout } from './kmsKeyPolicySelfLockout';

const key = (statements: object[]): CfnTemplate => ({
  Resources: {
    Key: {
      Type: 'AWS::KMS::Key',
      Properties: {
        KeyPolicy: { Version: '2012-10-17', Statement: statements },
      },
    },
  },
});

describe('kms-key-policy-self-lockout', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [kmsKeyPolicySelfLockout]);

  it('flags a blanket Deny on kms:PutKeyPolicy', () => {
    expect(
      run(
        key([
          {
            Effect: 'Deny',
            Principal: '*',
            Action: 'kms:PutKeyPolicy',
            Resource: '*',
          },
        ])
      )
    ).toHaveLength(1);
  });

  it('does not flag a Deny with a root/admin carveout', () => {
    expect(
      run(
        key([
          {
            Effect: 'Deny',
            Principal: '*',
            Action: 'kms:*',
            Resource: '*',
            Condition: {
              StringNotEquals: { 'aws:PrincipalAccount': '111122223333' },
            },
          },
        ])
      )
    ).toHaveLength(0);
  });

  it('does not flag the standard root-Allow key policy', () => {
    expect(
      run(
        key([
          {
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::111122223333:root' },
            Action: 'kms:*',
            Resource: '*',
          },
        ])
      )
    ).toHaveLength(0);
  });
});
