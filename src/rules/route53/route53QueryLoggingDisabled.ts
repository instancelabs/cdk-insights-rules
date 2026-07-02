import type { Rule } from '../../types';

/**
 * route53-query-logging-disabled
 *
 * Query logs are the DNS-level audit trail. Private zones are exempt (the
 * public-zone QueryLoggingConfig doesn't apply). A zone counts as covered
 * via an inline QueryLoggingConfig or a separate QueryLoggingConfig
 * resource targeting it.
 */
export const route53QueryLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'route53-query-logging-disabled',
    name: 'Route53 Query Logging Disabled',
    description:
      'Detects public Route53 hosted zones without DNS query logging.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::Route53::HostedZone',
      'AWS::Route53::QueryLoggingConfig',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html',
    remediationSteps: [
      'Set QueryLoggingConfig on the hosted zone (or add an AWS::Route53::QueryLoggingConfig) targeting a CloudWatch log group',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
  },

  check: (template, report) => {
    const entries = Object.entries(template.Resources ?? {});
    const loggedZoneIds = new Set<string>();
    for (const [, resource] of entries) {
      if (resource.Type !== 'AWS::Route53::QueryLoggingConfig') {
        continue;
      }
      const zone = resource.Properties?.HostedZoneId;
      if (typeof zone === 'string') {
        loggedZoneIds.add(zone);
      } else if (typeof zone?.Ref === 'string') {
        loggedZoneIds.add(zone.Ref);
      } else if (
        Array.isArray(zone?.['Fn::GetAtt']) &&
        typeof zone['Fn::GetAtt'][0] === 'string'
      ) {
        loggedZoneIds.add(zone['Fn::GetAtt'][0]);
      }
    }
    for (const [resourceId, resource] of entries) {
      if (resource.Type !== 'AWS::Route53::HostedZone') {
        continue;
      }
      const vpcs = resource.Properties?.VPCs;
      if (Array.isArray(vpcs) && vpcs.length > 0) {
        continue;
      }
      const hasLogging =
        loggedZoneIds.has(resourceId) ||
        Boolean(resource.Properties?.QueryLoggingConfig);
      if (!hasLogging) {
        report(resourceId, {
          issue:
            'Route53 public hosted zone does not have query logging enabled.',
          recommendation:
            'Enable query logging to CloudWatch Logs for DNS-level audit, troubleshooting, and abuse detection.',
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

new route53.CfnHostedZone(this, 'Zone', {
  name: 'example.com',
  queryLoggingConfig: {
    cloudWatchLogsLogGroupArn:
      'arn:aws:logs:us-east-1:111122223333:log-group:/aws/route53/example.com',
  },
});`,
  },
};
