import type { Rule } from '../../types';

/**
 * elb-deletion-protection-disabled
 *
 * A deleted load balancer takes its DNS name with it — deletion protection
 * is the guard against a stack update or console mistake taking the front
 * door offline.
 */
export const elbDeletionProtectionDisabled: Rule = {
  metadata: {
    ruleId: 'elb-deletion-protection-disabled',
    name: 'ELB Deletion Protection Disabled',
    description: 'Detects load balancers without deletion protection enabled.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    awsDocUrl:
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection',
    remediationSteps: [
      'Set the deletion_protection.enabled attribute to true (in CDK: deletionProtection: true)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ElasticLoadBalancingV2::LoadBalancer') {
        continue;
      }
      const attributes = resource.Properties?.LoadBalancerAttributes;
      const protectionEnabled =
        Array.isArray(attributes) &&
        attributes.some(
          (attribute) =>
            attribute?.Key === 'deletion_protection.enabled' &&
            (attribute?.Value === 'true' || attribute?.Value === true)
        );
      if (!protectionEnabled) {
        report(resourceId, {
          issue: 'Load balancer does not have deletion protection enabled.',
          recommendation:
            'Enable the deletion_protection.enabled attribute so the load balancer cannot be deleted by an accidental stack update or console action.',
        });
      }
    }
  },

  example: {
    flagged: `import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

new elbv2.CfnLoadBalancer(this, 'Alb', {
  type: 'application',
  subnets: ['subnet-12345678', 'subnet-87654321'],
});`,
    fixed: `import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

new elbv2.CfnLoadBalancer(this, 'Alb', {
  type: 'application',
  subnets: ['subnet-12345678', 'subnet-87654321'],
  loadBalancerAttributes: [
    { key: 'deletion_protection.enabled', value: 'true' },
  ],
});`,
  },
};
