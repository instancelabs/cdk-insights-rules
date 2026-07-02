import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3BucketPolicySelfLockout } from './s3BucketPolicySelfLockout';

const bucketPolicy = (statement: object): CfnTemplate => ({
  Resources: {
    Policy: {
      Type: 'AWS::S3::BucketPolicy',
      Properties: {
        Bucket: 'my-bucket',
        PolicyDocument: { Version: '2012-10-17', Statement: [statement] },
      },
    },
  },
});

describe('s3-bucket-policy-self-lockout', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3BucketPolicySelfLockout]);

  it('flags a blanket Deny on s3:* with no carveout', () => {
    expect(
      run(
        bucketPolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:*',
          Resource: 'arn:aws:s3:::my-bucket',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag the TLS-enforcement Deny (enforceSSL pattern)', () => {
    expect(
      run(
        bucketPolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:*',
          Resource: 'arn:aws:s3:::my-bucket',
          Condition: { Bool: { 'aws:SecureTransport': 'false' } },
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag a Deny with an admin carveout', () => {
    expect(
      run(
        bucketPolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:*',
          Resource: 'arn:aws:s3:::my-bucket',
          Condition: {
            ArnNotLike: {
              'aws:PrincipalArn': 'arn:aws:iam::111122223333:role/Admin',
            },
          },
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag a Deny scoped to object ARNs only', () => {
    expect(
      run(
        bucketPolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:*',
          Resource: 'arn:aws:s3:::my-bucket/private/*',
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag Allow statements or non-lockout actions', () => {
    expect(
      run(
        bucketPolicy({
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket',
        })
      )
    ).toHaveLength(0);
  });
});
