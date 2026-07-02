import type { Rule } from '../../types';

/**
 * cloudfront-waf-missing
 *
 * A distribution without a WebACL has no edge protection against common
 * exploits or volumetric abuse. Advisory by nature — static-asset-only
 * distributions may legitimately skip WAF; suppress the rule there.
 */
export const cloudfrontWafMissing: Rule = {
  metadata: {
    ruleId: 'cloudfront-waf-missing',
    name: 'CloudFront WAF Missing',
    description:
      'Detects CloudFront distributions without a WAF WebACL attached.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html',
    remediationSteps: [
      'Set DistributionConfig.WebACLId to a WAFv2 WebACL (CLOUDFRONT scope)',
      'If the distribution serves only public static assets, suppress this rule on the resource',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::CloudFront::Distribution') {
        continue;
      }
      if (!resource.Properties?.DistributionConfig?.WebACLId) {
        report(resourceId, {
          issue: 'CloudFront distribution has no WAF WebACL associated.',
          recommendation:
            'Attach a WAFv2 WebACL (CLOUDFRONT scope) to protect against common exploits, injection, and abusive traffic.',
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
    webAclId:
      'arn:aws:wafv2:us-east-1:111122223333:global/webacl/edge-acl/1234',
  },
});`,
  },
};
