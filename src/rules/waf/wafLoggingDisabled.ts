import type { Rule } from '../../types';

/** Logical ids a LoggingConfiguration's ResourceArn refers to. */
const referencedWebAclId = (resourceArn: unknown): string | undefined => {
  if (resourceArn && typeof resourceArn === 'object') {
    const obj = resourceArn as Record<string, unknown>;
    if (typeof obj.Ref === 'string') {
      return obj.Ref;
    }
    const getAtt = obj['Fn::GetAtt'];
    if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') {
      return getAtt[0];
    }
  }
  return undefined;
};

/**
 * waf-logging-disabled
 *
 * A WebACL without a LoggingConfiguration blocks and allows traffic with no
 * record of what it decided — useless for tuning or incident response.
 */
export const wafLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'waf-logging-disabled',
    name: 'WAF Logging Disabled',
    description:
      'Detects WAF WebACLs without an associated logging configuration.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::WAFv2::WebACL', 'AWS::WAFv2::LoggingConfiguration'],
    awsDocUrl:
      'https://docs.aws.amazon.com/waf/latest/developerguide/logging.html',
    remediationSteps: [
      'Add an AWS::WAFv2::LoggingConfiguration whose ResourceArn references the WebACL',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    const entries = Object.entries(template.Resources ?? {});
    const loggedAclIds = new Set<string>();
    for (const [, resource] of entries) {
      if (resource.Type !== 'AWS::WAFv2::LoggingConfiguration') {
        continue;
      }
      const target = referencedWebAclId(resource.Properties?.ResourceArn);
      if (target) {
        loggedAclIds.add(target);
      }
    }
    for (const [resourceId, resource] of entries) {
      if (resource.Type !== 'AWS::WAFv2::WebACL') {
        continue;
      }
      if (!loggedAclIds.has(resourceId)) {
        report(resourceId, {
          issue: 'WAF WebACL does not have logging configured.',
          recommendation:
            'Add a LoggingConfiguration for the WebACL so allow/block decisions are recorded for tuning and incident response.',
        });
      }
    }
  },

  example: {
    flagged: `import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

new wafv2.CfnWebACL(this, 'WebAcl', {
  scope: 'REGIONAL',
  defaultAction: { block: {} },
  visibilityConfig: {
    cloudWatchMetricsEnabled: true,
    metricName: 'web-acl',
    sampledRequestsEnabled: true,
  },
});`,
    fixed: `import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

const acl = new wafv2.CfnWebACL(this, 'WebAcl', {
  scope: 'REGIONAL',
  defaultAction: { block: {} },
  visibilityConfig: {
    cloudWatchMetricsEnabled: true,
    metricName: 'web-acl',
    sampledRequestsEnabled: true,
  },
});
new wafv2.CfnLoggingConfiguration(this, 'Logging', {
  resourceArn: acl.attrArn,
  logDestinationConfigs: [
    'arn:aws:logs:eu-west-2:111122223333:log-group:aws-waf-logs-acl',
  ],
});`,
  },
};
