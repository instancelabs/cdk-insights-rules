import type { Rule } from '../../types';

/**
 * route53-health-check-suboptimal
 *
 * HTTP health checks can pass while the HTTPS endpoint users actually hit is
 * broken; the standard 30-second interval takes up to 90s to fail over.
 */
export const route53HealthCheckSuboptimal: Rule = {
  metadata: {
    ruleId: 'route53-health-check-suboptimal',
    name: 'Route53 Health Check Suboptimal',
    description:
      'Detects Route53 health checks using plain HTTP or the slow standard request interval.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::Route53::HealthCheck'],
    awsDocUrl:
      'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html',
    remediationSteps: [
      'Use HTTPS (or HTTPS_STR_MATCH) health checks against TLS endpoints',
      'Use the fast (10 second) RequestInterval for critical endpoints',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Route53::HealthCheck') {
        continue;
      }
      const config = resource.Properties?.HealthCheckConfig;
      if (config?.Type === 'HTTP' || config?.Type === 'HTTP_STR_MATCH') {
        report(resourceId, {
          issue: 'Route53 health check uses HTTP instead of HTTPS.',
          recommendation:
            'Check the HTTPS endpoint users actually hit — an HTTP check can pass while TLS is broken.',
        });
      }
      if (config?.RequestInterval === 30) {
        report(resourceId, {
          issue:
            'Route53 health check uses the standard (30 second) request interval.',
          recommendation:
            'Use the fast (10 second) interval on critical endpoints so failover triggers sooner.',
        });
      }
    }
  },

  example: {
    flagged: `import * as route53 from 'aws-cdk-lib/aws-route53';

new route53.CfnHealthCheck(this, 'HealthCheck', {
  healthCheckConfig: {
    type: 'HTTP',
    fullyQualifiedDomainName: 'api.example.com',
    port: 80,
    resourcePath: '/health',
  },
});`,
    fixed: `import * as route53 from 'aws-cdk-lib/aws-route53';

new route53.CfnHealthCheck(this, 'HealthCheck', {
  healthCheckConfig: {
    type: 'HTTPS',
    fullyQualifiedDomainName: 'api.example.com',
    port: 443,
    resourcePath: '/health',
    requestInterval: 10,
  },
});`,
  },
};
