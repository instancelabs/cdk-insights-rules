import type { Rule } from '../../types';

/**
 * s3-bucket-encryption-aws-managed
 *
 * S3 applies SSE-S3 to every bucket by default (since Jan 2023), so a
 * missing BucketEncryption block is not "unencrypted" — it means encryption
 * is not customer-controlled. Compliance regimes that require auditable,
 * customer-managed keys (KMS with key policy + rotation) need it explicit.
 */
export const s3BucketEncryptionAwsManaged: Rule = {
  metadata: {
    ruleId: 's3-bucket-encryption-aws-managed',
    name: 'S3 Bucket Encryption Not Customer-Configured',
    description:
      'Detects S3 buckets without an explicit BucketEncryption configuration (SSE-S3 default applies, not customer-controlled).',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::S3::Bucket'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html',
    remediationSteps: [
      'Set BucketEncryption explicitly — SSE-KMS with a customer-managed key where compliance requires auditable key control (in CDK: encryption: s3.BucketEncryption.KMS)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::S3::Bucket' &&
        !resource.Properties?.BucketEncryption
      ) {
        report(resourceId, {
          issue:
            'S3 bucket has no explicit encryption configuration (the SSE-S3 default applies).',
          recommendation:
            'Configure BucketEncryption explicitly — use SSE-KMS with a customer-managed key where key rotation and access must be auditable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {});`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {
  bucketEncryption: {
    serverSideEncryptionConfiguration: [
      {
        serverSideEncryptionByDefault: {
          sseAlgorithm: 'aws:kms',
          kmsMasterKeyId:
            'arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        },
      },
    ],
  },
});`,
  },
};
