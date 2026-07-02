import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { kmsKeyPolicyPublic } from './kmsKeyPolicyPublic';

const key = (statement: object): CfnTemplate => ({
  Resources: {
    Key: {
      Type: 'AWS::KMS::Key',
      Properties: {
        KeyPolicy: { Version: '2012-10-17', Statement: [statement] },
      },
    },
  },
});

describe('kms-key-policy-public', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [kmsKeyPolicyPublic]);

  it('flags an Allow to a wildcard principal', () => {
    expect(
      run(
        key({ Effect: 'Allow', Principal: '*', Action: 'kms:*', Resource: '*' })
      )
    ).toHaveLength(1);
  });

  it('flags an Allow to { AWS: "*" }', () => {
    expect(
      run(
        key({
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:Decrypt',
          Resource: '*',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag a Deny to a wildcard principal (lockout guard)', () => {
    expect(
      run(
        key({ Effect: 'Deny', Principal: '*', Action: 'kms:*', Resource: '*' })
      )
    ).toHaveLength(0);
  });

  it('does not flag a wildcard scoped by a condition', () => {
    expect(
      run(
        key({
          Effect: 'Allow',
          Principal: '*',
          Action: 'kms:Decrypt',
          Resource: '*',
          Condition: { StringEquals: { 'kms:CallerAccount': '111122223333' } },
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag an account-root principal', () => {
    expect(
      run(
        key({
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::111122223333:root' },
          Action: 'kms:*',
          Resource: '*',
        })
      )
    ).toHaveLength(0);
  });
});
