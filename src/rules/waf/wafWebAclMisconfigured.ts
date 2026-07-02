import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * waf-webacl-misconfigured
 *
 * Two decidable misconfigurations: a WebACL that defaults to Allow while
 * defining no rules at all (it inspects nothing — pure theatre), and a
 * WebACL without CloudWatch metrics (attacks invisible). A default-Allow
 * WebACL *with* rules is the standard managed-rule-group shape and is not
 * flagged — the CDK Insights product flags it, which false-positives on the
 * most common legitimate WAF configuration.
 */
export const wafWebAclMisconfigured: Rule = {
  metadata: {
    ruleId: 'waf-webacl-misconfigured',
    name: 'WAF WebACL Misconfigured',
    description:
      'Detects WAF WebACLs with no rules defined, or running without CloudWatch metrics.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::WAFv2::WebACL'],
    awsDocUrl:
      'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html',
    remediationSteps: [
      'Add rules (e.g. AWS managed rule groups) so the WebACL actually inspects traffic',
      'Enable CloudWatchMetricsEnabled in VisibilityConfig',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::WAFv2::WebACL') {
        continue;
      }
      const props = resource.Properties ?? {};
      const rules = props.Rules;
      const hasRules = Array.isArray(rules) && rules.length > 0;
      if (!hasRules) {
        report(resourceId, {
          issue: props.DefaultAction?.Allow
            ? 'WAF WebACL defaults to Allow and defines no rules — it inspects nothing.'
            : 'WAF WebACL defines no rules.',
          recommendation:
            'Add rules (e.g. AWS managed rule groups) so the WebACL actually inspects traffic.',
        });
      }
      const metricsEnabled = props.VisibilityConfig?.CloudWatchMetricsEnabled;
      if (!isIntrinsic(metricsEnabled) && asBoolean(metricsEnabled) !== true) {
        report(resourceId, {
          issue: 'WAF WebACL does not have CloudWatch metrics enabled.',
          recommendation:
            'Enable CloudWatchMetricsEnabled in VisibilityConfig so WAF activity and potential attacks are observable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

new wafv2.CfnWebACL(this, 'WebAcl', {
  scope: 'REGIONAL',
  defaultAction: { allow: {} },
  visibilityConfig: {
    cloudWatchMetricsEnabled: false,
    metricName: 'web-acl',
    sampledRequestsEnabled: true,
  },
});`,
    fixed: `import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

new wafv2.CfnWebACL(this, 'WebAcl', {
  scope: 'REGIONAL',
  defaultAction: { allow: {} },
  visibilityConfig: {
    cloudWatchMetricsEnabled: true,
    metricName: 'web-acl',
    sampledRequestsEnabled: true,
  },
  rules: [
    {
      name: 'AWSManagedRulesCommonRuleSet',
      priority: 0,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesCommonRuleSet',
        },
      },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'common-rules',
        sampledRequestsEnabled: true,
      },
    },
  ],
});`,
  },
};
