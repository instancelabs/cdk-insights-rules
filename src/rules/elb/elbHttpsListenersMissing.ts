import type { Rule } from '../../types';

/**
 * elb-https-listeners-missing
 *
 * An ALB/NLB listener speaking plain HTTP either terminates user traffic
 * unencrypted or must redirect to HTTPS. An HTTP listener whose default
 * action redirects to HTTPS is the standard port-80 shape and is not flagged.
 */
export const elbHttpsListenersMissing: Rule = {
  metadata: {
    ruleId: 'elb-https-listeners-missing',
    name: 'ELB Listener Without HTTPS',
    description:
      'Detects load balancer HTTP listeners that neither use HTTPS nor redirect to it.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::Listener'],
    awsDocUrl:
      'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
    remediationSteps: [
      'Use an HTTPS listener with an ACM certificate for application traffic',
      'Keep port 80 only as a redirect listener (default action: redirect to HTTPS 443)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ElasticLoadBalancingV2::Listener') {
        continue;
      }
      if (resource.Properties?.Protocol !== 'HTTP') {
        continue;
      }
      const defaultActions = resource.Properties?.DefaultActions;
      const redirectsToHttps =
        Array.isArray(defaultActions) &&
        defaultActions.some(
          (action) =>
            action?.Type === 'redirect' &&
            action?.RedirectConfig?.Protocol === 'HTTPS'
        );
      if (!redirectsToHttps) {
        report(resourceId, {
          issue:
            'Load balancer listener serves plain HTTP and does not redirect to HTTPS.',
          recommendation:
            'Terminate TLS with an HTTPS listener and an ACM certificate; keep HTTP listeners only as redirects to HTTPS.',
        });
      }
    }
  },

  example: {
    flagged: `import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

new elbv2.CfnListener(this, 'Listener', {
  loadBalancerArn:
    'arn:aws:elasticloadbalancing:eu-west-2:111122223333:loadbalancer/app/my-alb/1234567890abcdef',
  port: 80,
  protocol: 'HTTP',
  defaultActions: [
    {
      type: 'forward',
      targetGroupArn:
        'arn:aws:elasticloadbalancing:eu-west-2:111122223333:targetgroup/app/1234567890abcdef',
    },
  ],
});`,
    fixed: `import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

new elbv2.CfnListener(this, 'Listener', {
  loadBalancerArn:
    'arn:aws:elasticloadbalancing:eu-west-2:111122223333:loadbalancer/app/my-alb/1234567890abcdef',
  port: 80,
  protocol: 'HTTP',
  defaultActions: [
    {
      type: 'redirect',
      redirectConfig: {
        protocol: 'HTTPS',
        port: '443',
        statusCode: 'HTTP_301',
      },
    },
  ],
});`,
  },
};
