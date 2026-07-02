import type { Rule } from '../../types';

/**
 * s3-bucket-access-logging-disabled
 *
 * Server access logs are the only record of object-level access for
 * forensics without CloudTrail data events. CIS AWS Foundations 2.1.2.
 */
export const s3BucketAccessLoggingDisabled: Rule = {
  metadata: {
    ruleId: 's3-bucket-access-logging-disabled',
    name: 'S3 Bucket Access Logging Disabled',
    description: 'Detects S3 buckets without server access logging configured.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::S3::Bucket'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html',
    remediationSteps: [
      'Set LoggingConfiguration.DestinationBucketName to a separate log bucket (in CDK: serverAccessLogsBucket)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::S3::Bucket') {
        continue;
      }
      if (resource.Properties?.LoggingConfiguration?.DestinationBucketName) {
        continue;
      }
      report(resourceId, {
        issue: 'S3 bucket has no server access logging configured.',
        recommendation:
          'Set LoggingConfiguration.DestinationBucketName to a dedicated log bucket so object-level access is recorded for forensics (CIS 2.1.2).',
      });
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {});`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {
  loggingConfiguration: {
    destinationBucketName: 'my-access-logs-bucket',
  },
});`,
  },
};
