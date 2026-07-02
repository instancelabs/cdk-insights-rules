import type { Rule } from '../../types';

/**
 * elb-logging-disabled
 *
 * Without access logs there is no request-level record for incident
 * forensics or abuse analysis. Enabled via the load balancer attribute
 * `access_logs.s3.enabled`.
 */
export const elbLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'elb-logging-disabled',
    name: 'ELB Access Logging Disabled',
    description: 'Detects load balancers without access logging to S3 enabled.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    awsDocUrl:
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html',
    remediationSteps: [
      'Set the access_logs.s3.enabled attribute to true with an access_logs.s3.bucket (in CDK: logAccessLogs())',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ElasticLoadBalancingV2::LoadBalancer') {
        continue;
      }
      const attributes = resource.Properties?.LoadBalancerAttributes;
      const hasAccessLogging =
        Array.isArray(attributes) &&
        attributes.some(
          (attribute) =>
            attribute?.Key === 'access_logs.s3.enabled' &&
            (attribute?.Value === 'true' || attribute?.Value === true)
        );
      if (!hasAccessLogging) {
        report(resourceId, {
          issue: 'Load balancer does not have access logging enabled.',
          recommendation:
            'Enable access logs to S3 (attribute access_logs.s3.enabled) so request-level traffic is available for auditing and forensics.',
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
    { key: 'access_logs.s3.enabled', value: 'true' },
    { key: 'access_logs.s3.bucket', value: 'my-alb-logs' },
  ],
});`,
  },
};
