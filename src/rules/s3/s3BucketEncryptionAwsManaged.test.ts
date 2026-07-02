import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3BucketEncryptionAwsManaged } from './s3BucketEncryptionAwsManaged';

describe('s3-bucket-encryption-aws-managed', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3BucketEncryptionAwsManaged]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::S3::Bucket', Properties: { ...properties } },
    },
  });

  it('flags a bucket without explicit encryption', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('does not flag explicit encryption (KMS or SSE-S3)', () => {
    expect(
      run(
        res({
          BucketEncryption: {
            ServerSideEncryptionConfiguration: [
              { ServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' } },
            ],
          },
        })
      )
    ).toHaveLength(0);
  });
});
