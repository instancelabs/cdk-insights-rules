import type { Rule } from '../../types';

const CRITICAL_BUCKET_PATTERN =
  /\b(prod|production|critical|backup|dr|disaster|recovery|primary)\b/i;

/**
 * s3-replication-missing
 *
 * Scoped to buckets that *say* they matter: names matching prod/critical/
 * backup/dr patterns. Those without cross-region replication have no
 * geographic redundancy for data that presumably needs it.
 */
export const s3ReplicationMissing: Rule = {
  metadata: {
    ruleId: 's3-replication-missing',
    name: 'S3 Replication Missing On Critical Bucket',
    description:
      'Detects production/critical-named S3 buckets without cross-region replication.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::S3::Bucket'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html',
    remediationSteps: [
      'Configure ReplicationConfiguration to a bucket in another region (requires versioning on both)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::S3::Bucket') {
        continue;
      }
      const bucketName = resource.Properties?.BucketName;
      const nameToTest =
        typeof bucketName === 'string' ? bucketName : resourceId;
      if (!CRITICAL_BUCKET_PATTERN.test(nameToTest)) {
        continue;
      }
      const rules = resource.Properties?.ReplicationConfiguration?.Rules;
      if (!Array.isArray(rules) || rules.length === 0) {
        report(resourceId, {
          issue:
            'Critical-named S3 bucket has no cross-region replication configured.',
          recommendation:
            'Enable ReplicationConfiguration to another region for geographic redundancy on data the bucket name marks as critical.',
        });
      }
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {
  bucketName: 'prod-customer-data',
  versioningConfiguration: { status: 'Enabled' },
});`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {
  bucketName: 'prod-customer-data',
  versioningConfiguration: { status: 'Enabled' },
  replicationConfiguration: {
    role: 'arn:aws:iam::111122223333:role/replication-role',
    rules: [
      {
        status: 'Enabled',
        destination: { bucket: 'arn:aws:s3:::prod-customer-data-replica' },
      },
    ],
  },
});`,
  },
};
