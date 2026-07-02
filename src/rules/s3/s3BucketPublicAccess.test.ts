import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3BucketPublicAccess } from './s3BucketPublicAccess';

describe('s3-bucket-public-access', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3BucketPublicAccess]);

  it('flags a bucket with no PublicAccessBlockConfiguration', () => {
    expect(
      run({
        Resources: { Bucket: { Type: 'AWS::S3::Bucket', Properties: {} } },
      })
    ).toHaveLength(1);
  });

  it('flags a bucket with a partially disabled block, naming the flags', () => {
    const findings = run({
      Resources: {
        Bucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              BlockPublicPolicy: false,
              IgnorePublicAcls: true,
              RestrictPublicBuckets: true,
            },
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('BlockPublicPolicy');
    expect(findings[0].issue).not.toContain('BlockPublicAcls,');
  });

  it('does not flag a bucket with all four settings enabled (boolean or string form)', () => {
    expect(
      run({
        Resources: {
          Bucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              PublicAccessBlockConfiguration: {
                BlockPublicAcls: true,
                BlockPublicPolicy: 'true',
                IgnorePublicAcls: true,
                RestrictPublicBuckets: true,
              },
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag flags set via intrinsics (undecidable)', () => {
    expect(
      run({
        Resources: {
          Bucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              PublicAccessBlockConfiguration: {
                BlockPublicAcls: true,
                BlockPublicPolicy: { 'Fn::If': ['Cond', true, false] },
                IgnorePublicAcls: true,
                RestrictPublicBuckets: true,
              },
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
