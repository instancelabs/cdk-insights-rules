import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3ReplicationMissing } from './s3ReplicationMissing';

describe('s3-replication-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3ReplicationMissing]);

  const bucket = (properties: object): CfnTemplate => ({
    Resources: {
      Bucket: { Type: 'AWS::S3::Bucket', Properties: properties },
    },
  });

  it('flags critical-named buckets without replication', () => {
    expect(run(bucket({ BucketName: 'prod-data' }))).toHaveLength(1);
    expect(run(bucket({ BucketName: 'dr-archive' }))).toHaveLength(1);
  });

  it('does not flag non-critical names or replicated buckets', () => {
    expect(run(bucket({ BucketName: 'scratch-space' }))).toHaveLength(0);
    expect(
      run(
        bucket({
          BucketName: 'prod-data',
          ReplicationConfiguration: {
            Role: 'arn:role',
            Rules: [{ Status: 'Enabled', Destination: { Bucket: 'arn:b' } }],
          },
        })
      )
    ).toHaveLength(0);
  });
});
