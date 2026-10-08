import type { Rule } from '../../types';

/**
 * s3-bucket-access-logging-disabled
 *
 * Server access logging is one audit option; other coverage may exist.
 */
export const s3BucketAccessLoggingDisabled: Rule = {
  metadata: {
    ruleId: 's3-bucket-access-logging-disabled',
    name: 'S3 Bucket Access Logging Disabled',
    description: 'Detects S3 buckets without server access logging configured.',
    severity: 'LOW',
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
          'Check existing audit coverage, including CloudTrail data events, and retention requirements. If server access logs are needed, set LoggingConfiguration.DestinationBucketName to a dedicated log bucket.',
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
