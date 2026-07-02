import type { Rule } from '../../types';

const OUTDATED_TLS_VERSIONS = ['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016'];

/**
 * cloudfront-tls-outdated
 *
 * With a custom certificate, MinimumProtocolVersion defaults to TLSv1 —
 * protocols with known weaknesses. Distributions on the default CloudFront
 * certificate can't set a minimum version and are exempt.
 */
export const cloudfrontTlsOutdated: Rule = {
  metadata: {
    ruleId: 'cloudfront-tls-outdated',
    name: 'CloudFront TLS Version Outdated',
    description:
      'Detects CloudFront distributions with a custom certificate whose minimum TLS version is outdated or left at the TLSv1 default.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
    remediationSteps: [
      'Set ViewerCertificate.MinimumProtocolVersion to TLSv1.2_2021 or later',
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
      const certificate =
        resource.Properties?.DistributionConfig?.ViewerCertificate;
      // The default CloudFront certificate cannot set a minimum version.
      if (!certificate || certificate.CloudFrontDefaultCertificate) {
        continue;
      }
      const minVersion = certificate.MinimumProtocolVersion;
      const hasCustomCert =
        Boolean(certificate.AcmCertificateArn) ||
        Boolean(certificate.IamCertificateId);
      const isOutdated =
        (typeof minVersion === 'string' &&
          OUTDATED_TLS_VERSIONS.includes(minVersion)) ||
        (hasCustomCert && minVersion === undefined);
      if (isOutdated) {
        report(resourceId, {
          issue: `CloudFront distribution uses an outdated minimum TLS version (${minVersion ?? 'TLSv1 default'}).`,
          recommendation:
            'Set MinimumProtocolVersion to TLSv1.2_2021 or later — older TLS versions have known vulnerabilities.',
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
    viewerCertificate: {
      acmCertificateArn:
        'arn:aws:acm:us-east-1:111122223333:certificate/abcd',
      sslSupportMethod: 'sni-only',
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
    viewerCertificate: {
      acmCertificateArn:
        'arn:aws:acm:us-east-1:111122223333:certificate/abcd',
      sslSupportMethod: 'sni-only',
      minimumProtocolVersion: 'TLSv1.2_2021',
    },
  },
});`,
  },
};
