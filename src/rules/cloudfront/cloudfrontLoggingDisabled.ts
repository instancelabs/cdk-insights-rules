import type { Rule } from '../../types';

/**
 * cloudfront-logging-disabled
 *
 * Without access logs there is no record of viewer requests for forensics
 * or abuse analysis at the edge.
 */
export const cloudfrontLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'cloudfront-logging-disabled',
    name: 'CloudFront Access Logging Disabled',
    description:
      'Detects CloudFront distributions without access logging configured.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html',
    remediationSteps: [
      'Configure DistributionConfig.Logging with an S3 bucket (in CDK: enableLogging / logBucket)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::CloudFront::Distribution') {
        continue;
      }
      if (!resource.Properties?.DistributionConfig?.Logging?.Bucket) {
        report(resourceId, {
          issue:
            'CloudFront distribution does not have access logging enabled.',
          recommendation:
            'Enable access logging to an S3 bucket so viewer requests are recorded for auditing and forensics.',
        });
      }
    }
  },

  example: {
    flagged: `import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';

new cloudfront.CfnDistribution(this, 'Distribution', {
  distributionConfig: {
    enabled: true,
    defaultCacheBehavior: {
      targetOriginId: 'origin',
      viewerProtocolPolicy: 'redirect-to-https',
    },
  },
});`,
    fixed: `import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';

new cloudfront.CfnDistribution(this, 'Distribution', {
  distributionConfig: {
    enabled: true,
    defaultCacheBehavior: {
      targetOriginId: 'origin',
      viewerProtocolPolicy: 'redirect-to-https',
    },
    logging: {
      bucket: 'my-cf-logs.s3.amazonaws.com',
    },
  },
});`,
  },
};
