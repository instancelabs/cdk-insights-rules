import type { Rule } from '../../types';

/**
 * s3-bucket-versioning-disabled
 *
 * An S3 bucket without versioning cannot recover overwritten or deleted
 * objects. Versioning keeps prior object versions, protecting against
 * accidental loss and ransomware-style overwrites.
 */
export const s3BucketVersioningDisabled: Rule = {
  metadata: {
    ruleId: 's3-bucket-versioning-disabled',
    name: 'S3 Bucket Versioning Disabled',
    description:
      'Detects S3 buckets without versioning enabled, leaving overwritten or deleted objects unrecoverable.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::S3::Bucket'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html',
    remediationSteps: [
      'Set VersioningConfiguration.Status to Enabled on the bucket',
      'Add lifecycle rules to expire noncurrent versions and control cost',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::S3::Bucket' &&
        resource.Properties?.VersioningConfiguration?.Status !== 'Enabled'
      ) {
        report(resourceId, {
          issue: 'S3 bucket does not have versioning enabled.',
          recommendation:
            'Enable versioning (VersioningConfiguration.Status = Enabled) so overwritten or deleted objects can be recovered, protecting against accidental loss and ransomware.',
        });
      }
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.Bucket(this, 'Bucket');`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.Bucket(this, 'Bucket', { versioned: true });`,
  },
};
