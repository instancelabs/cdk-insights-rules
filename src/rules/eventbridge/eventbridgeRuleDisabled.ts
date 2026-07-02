import type { Rule } from '../../types';

/**
 * eventbridge-rule-disabled
 *
 * A disabled rule sits in the template looking configured while matching
 * nothing — usually a leftover from debugging that never got re-enabled.
 */
export const eventbridgeRuleDisabled: Rule = {
  metadata: {
    ruleId: 'eventbridge-rule-disabled',
    name: 'EventBridge Rule Disabled',
    description:
      'Detects EventBridge rules with State DISABLED, which match no events.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::Events::Rule'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html',
    remediationSteps: [
      'Set State to ENABLED, or delete the rule if it is no longer needed',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::Events::Rule' &&
        resource.Properties?.State === 'DISABLED'
      ) {
        report(resourceId, {
          issue: 'EventBridge rule is disabled.',
          recommendation:
            'Set State to ENABLED so the rule matches events — or remove it if it is intentionally retired.',
        });
      }
    }
  },

  example: {
    flagged: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnRule(this, 'Rule', {
  scheduleExpression: 'rate(5 minutes)',
  state: 'DISABLED',
  targets: [
    {
      id: 'worker',
      arn: 'arn:aws:lambda:eu-west-2:111122223333:function:worker',
      deadLetterConfig: {
        arn: 'arn:aws:sqs:eu-west-2:111122223333:events-dlq',
      },
    },
  ],
});`,
    fixed: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnRule(this, 'Rule', {
  scheduleExpression: 'rate(5 minutes)',
  state: 'ENABLED',
  targets: [
    {
      id: 'worker',
      arn: 'arn:aws:lambda:eu-west-2:111122223333:function:worker',
      deadLetterConfig: {
        arn: 'arn:aws:sqs:eu-west-2:111122223333:events-dlq',
      },
    },
  ],
});`,
  },
};
