import type { Rule } from '../../types';

const OUTDATED_SECURITY_POLICIES = new Set([
  'ELBSecurityPolicy-2016-08',
  'ELBSecurityPolicy-TLS-1-0-2015-04',
  'ELBSecurityPolicy-TLS-1-1-2017-01',
  'ELBSecurityPolicy-2015-05',
  'ELBSecurityPolicy-FS-2018-06',
  'ELBSecurityPolicy-FS-1-1-2019-08',
]);

const DEFAULT_SSL_POLICY = 'ELBSecurityPolicy-2016-08';

/**
 * elb-security-policy-outdated
 *
 * HTTPS/TLS listeners without an explicit SslPolicy get
 * ELBSecurityPolicy-2016-08, which still negotiates TLS 1.0/1.1.
 */
export const elbSecurityPolicyOutdated: Rule = {
  metadata: {
    ruleId: 'elb-security-policy-outdated',
    name: 'ELB Security Policy Outdated',
    description:
      'Detects HTTPS/TLS listeners using outdated SSL policies (including the TLS 1.0-era default).',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::Listener'],
    awsDocUrl:
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies',
    remediationSteps: [
      'Set SslPolicy to ELBSecurityPolicy-TLS13-1-2-2021-06 (TLS 1.3) or at minimum ELBSecurityPolicy-TLS-1-2-2017-01',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ElasticLoadBalancingV2::Listener') {
        continue;
      }
      const protocol = resource.Properties?.Protocol;
      if (protocol !== 'HTTPS' && protocol !== 'TLS') {
        continue;
      }
      const sslPolicy = resource.Properties?.SslPolicy;
      if (sslPolicy !== undefined && typeof sslPolicy !== 'string') {
        continue; // intrinsic — undecidable
      }
      const effective = sslPolicy ?? DEFAULT_SSL_POLICY;
      if (OUTDATED_SECURITY_POLICIES.has(effective)) {
        report(resourceId, {
          issue: `Load balancer listener uses outdated security policy ${sslPolicy ?? `${DEFAULT_SSL_POLICY} (default)`}.`,
          recommendation:
            'Set SslPolicy to ELBSecurityPolicy-TLS13-1-2-2021-06 (or at minimum a TLS 1.2-only policy) — the old default still negotiates TLS 1.0/1.1.',
        });
      }
    }
  },

  example: {
    flagged: `import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

new elbv2.CfnListener(this, 'Listener', {
  loadBalancerArn:
    'arn:aws:elasticloadbalancing:eu-west-2:111122223333:loadbalancer/app/my-alb/1234567890abcdef',
  port: 443,
  protocol: 'HTTPS',
  certificates: [{ certificateArn: 'arn:aws:acm:eu-west-2:1:certificate/x' }],
  defaultActions: [{ type: 'forward', targetGroupArn: 'arn:tg' }],
});`,
    fixed: `import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

new elbv2.CfnListener(this, 'Listener', {
  loadBalancerArn:
    'arn:aws:elasticloadbalancing:eu-west-2:111122223333:loadbalancer/app/my-alb/1234567890abcdef',
  port: 443,
  protocol: 'HTTPS',
  sslPolicy: 'ELBSecurityPolicy-TLS13-1-2-2021-06',
  certificates: [{ certificateArn: 'arn:aws:acm:eu-west-2:1:certificate/x' }],
  defaultActions: [{ type: 'forward', targetGroupArn: 'arn:tg' }],
});`,
  },
};
