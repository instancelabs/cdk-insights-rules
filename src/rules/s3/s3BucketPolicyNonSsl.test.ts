import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3BucketPolicyNonSsl } from './s3BucketPolicyNonSsl';

const bucketPolicy = (statements: object[]): CfnTemplate => ({
  Resources: {
    Policy: {
      Type: 'AWS::S3::BucketPolicy',
      Properties: {
        Bucket: 'my-bucket',
        PolicyDocument: { Version: '2012-10-17', Statement: statements },
      },
    },
  },
});

const tlsDeny = {
  Effect: 'Deny',
  Principal: '*',
  Action: 's3:*',
  Resource: ['arn:aws:s3:::my-bucket', 'arn:aws:s3:::my-bucket/*'],
  Condition: { Bool: { 'aws:SecureTransport': 'false' } },
};

describe('s3-bucket-policy-non-ssl', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3BucketPolicyNonSsl]);

  it('flags a bucket policy without a TLS-enforcement Deny', () => {
    expect(
      run(
        bucketPolicy([
          {
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::1:root' },
            Action: 's3:GetObject',
            Resource: 'arn:aws:s3:::my-bucket/*',
          },
        ])
      )
    ).toHaveLength(1);
  });

  it('flags a TLS Deny that covers only objects, not the bucket', () => {
    expect(
      run(bucketPolicy([{ ...tlsDeny, Resource: 'arn:aws:s3:::my-bucket/*' }]))
    ).toHaveLength(1);
  });

  it('does not flag the enforceSSL shape', () => {
    expect(run(bucketPolicy([tlsDeny]))).toHaveLength(0);
  });
});
