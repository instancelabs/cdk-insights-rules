import type { Rule } from '../../types';

/**
 * route53-dnssec-disabled
 *
 * DNSSEC signs DNS responses against spoofing and cache poisoning. Private
 * hosted zones (VPCs attached) don't support DNSSEC and are exempt. A zone
 * counts as covered when an AWS::Route53::DNSSEC in the template targets it.
 */
export const route53DnssecDisabled: Rule = {
  metadata: {
    ruleId: 'route53-dnssec-disabled',
    name: 'Route53 DNSSEC Disabled',
    description:
      'Detects public Route53 hosted zones without DNSSEC signing enabled.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Route53::HostedZone', 'AWS::Route53::DNSSEC'],
    awsDocUrl:
      'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html',
    remediationSteps: [
      'Add an AWS::Route53::DNSSEC resource for the hosted zone (with a KMS key-signing key)',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    const entries = Object.entries(template.Resources ?? {});
    const signedZoneIds = new Set<string>();
    for (const [, resource] of entries) {
      if (resource.Type !== 'AWS::Route53::DNSSEC') {
        continue;
      }
      const zone = resource.Properties?.HostedZoneId;
      if (typeof zone === 'string') {
        signedZoneIds.add(zone);
      } else if (typeof zone?.Ref === 'string') {
        signedZoneIds.add(zone.Ref);
      } else if (
        Array.isArray(zone?.['Fn::GetAtt']) &&
        typeof zone['Fn::GetAtt'][0] === 'string'
      ) {
        signedZoneIds.add(zone['Fn::GetAtt'][0]);
      }
    }
    for (const [resourceId, resource] of entries) {
      if (resource.Type !== 'AWS::Route53::HostedZone') {
        continue;
      }
      // Private zones (VPCs attached) do not support DNSSEC.
      const vpcs = resource.Properties?.VPCs;
      if (Array.isArray(vpcs) && vpcs.length > 0) {
        continue;
      }
      if (!signedZoneIds.has(resourceId)) {
        report(resourceId, {
          issue:
            'Route53 public hosted zone does not have DNSSEC signing enabled.',
          recommendation:
            'Enable DNSSEC signing so DNS responses are cryptographically verifiable against spoofing and cache poisoning.',
        });
      }
    }
  },

  example: {
    flagged: `import * as route53 from 'aws-cdk-lib/aws-route53';

new route53.CfnHostedZone(this, 'Zone', {
  name: 'example.com',
});`,
    fixed: `import * as route53 from 'aws-cdk-lib/aws-route53';

const zone = new route53.CfnHostedZone(this, 'Zone', {
  name: 'example.com',
});
new route53.CfnDNSSEC(this, 'Dnssec', {
  hostedZoneId: zone.attrId,
});`,
  },
};
