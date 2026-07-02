import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3BucketAccessLoggingDisabled } from './s3BucketAccessLoggingDisabled';

describe('s3-bucket-access-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3BucketAccessLoggingDisabled]);

  it('flags a bucket without a logging configuration', () => {
    expect(
      run({
        Resources: { Bucket: { Type: 'AWS::S3::Bucket', Properties: {} } },
      })
    ).toHaveLength(1);
  });

  it('does not flag a bucket with a logging destination (literal or intrinsic)', () => {
    expect(
      run({
        Resources: {
          Literal: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              LoggingConfiguration: { DestinationBucketName: 'logs' },
            },
          },
          Intrinsic: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              LoggingConfiguration: {
                DestinationBucketName: { Ref: 'LogBucket' },
              },
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
