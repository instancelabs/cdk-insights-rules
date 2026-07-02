import type { Rule } from '../../types';

/**
 * cloudfront-https-only
 *
 * A distribution whose default (or any) cache behavior sets
 * `ViewerProtocolPolicy: allow-all` serves content over plain HTTP.
 */
export const cloudfrontHttpsOnly: Rule = {
  metadata: {
    ruleId: 'cloudfront-https-only',
    name: 'CloudFront Allows HTTP Traffic',
    description:
      'Detects CloudFront distributions with a cache behavior that allows plain HTTP (ViewerProtocolPolicy allow-all).',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html',
    remediationSteps: [
      'Set ViewerProtocolPolicy to redirect-to-https (or https-only) on the default and every additional cache behavior',
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
      const config = resource.Properties?.DistributionConfig;
      const behaviors: { ViewerProtocolPolicy?: unknown }[] = [
        config?.DefaultCacheBehavior,
        ...(Array.isArray(config?.CacheBehaviors) ? config.CacheBehaviors : []),
      ].filter(Boolean);

      if (
        behaviors.some(
          (behavior) => behavior?.ViewerProtocolPolicy === 'allow-all'
        )
      ) {
        report(resourceId, {
          issue:
            'CloudFront distribution allows plain HTTP traffic (a cache behavior sets ViewerProtocolPolicy to allow-all).',
          recommendation:
            'Set ViewerProtocolPolicy to redirect-to-https or https-only so viewer traffic is always encrypted.',
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
      viewerProtocolPolicy: 'allow-all',
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
  },
});`,
  },
};
