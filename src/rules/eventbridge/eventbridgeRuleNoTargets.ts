import type { Rule } from '../../types';

/**
 * eventbridge-rule-no-targets
 *
 * A rule with no targets matches events and silently drops them. (Ported
 * from the product's eventbridge-dlq-missing, whose implementation actually
 * checks for missing targets — the open catalog names the rule for what it
 * detects; the DLQ concern lives in eventbridge-target-dlq-missing.)
 */
export const eventbridgeRuleNoTargets: Rule = {
  metadata: {
    ruleId: 'eventbridge-rule-no-targets',
    name: 'EventBridge Rule Without Targets',
    description:
      'Detects EventBridge rules with no targets, which match events and silently drop them.',
    severity: 'HIGH',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::Events::Rule'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html',
    remediationSteps: [
      'Add at least one target (Lambda, SQS, SNS, Step Functions, ...) to process matched events',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Events::Rule') {
        continue;
      }
      const targets = resource.Properties?.Targets;
      if (!targets || (Array.isArray(targets) && targets.length === 0)) {
        report(resourceId, {
          issue:
            'EventBridge rule has no targets — matched events are silently dropped.',
          recommendation:
            'Add at least one target so matched events actually trigger processing.',
        });
      }
    }
  },

  example: {
    flagged: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnRule(this, 'Rule', {
  scheduleExpression: 'rate(5 minutes)',
});`,
    fixed: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnRule(this, 'Rule', {
  scheduleExpression: 'rate(5 minutes)',
  targets: [
    {
      id: 'worker',
      arn: 'arn:aws:lambda:eu-west-2:111122223333:function:worker',
    },
  ],
});`,
  },
};
