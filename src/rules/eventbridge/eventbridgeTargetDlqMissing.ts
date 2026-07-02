import type { Rule } from '../../types';

/**
 * eventbridge-target-dlq-missing
 *
 * When EventBridge exhausts its delivery retries to a target, the event is
 * lost unless the target has a DeadLetterConfig. Advisory (LOW) — many
 * targets tolerate loss; wire DLQs on the ones that don't.
 */
export const eventbridgeTargetDlqMissing: Rule = {
  metadata: {
    ruleId: 'eventbridge-target-dlq-missing',
    name: 'EventBridge Target Without DLQ',
    description:
      'Detects EventBridge rule targets without a dead-letter queue for failed deliveries.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::Events::Rule'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html',
    remediationSteps: [
      'Set DeadLetterConfig.Arn (an SQS queue) on each target whose events must not be lost',
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
      if (!Array.isArray(targets) || targets.length === 0) {
        continue;
      }
      const withoutDlq = targets.filter(
        (target) => !target?.DeadLetterConfig?.Arn
      );
      if (withoutDlq.length > 0) {
        report(resourceId, {
          issue: `EventBridge rule has ${withoutDlq.length} target(s) without a dead-letter queue — events are lost when delivery retries are exhausted.`,
          recommendation:
            'Set DeadLetterConfig.Arn on targets whose events must not be lost.',
        });
      }
    }
  },

  example: {
    flagged: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnRule(this, 'Rule', {
  scheduleExpression: 'rate(5 minutes)',
  targets: [
    {
      id: 'worker',
      arn: 'arn:aws:lambda:eu-west-2:111122223333:function:worker',
    },
  ],
});`,
    fixed: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnRule(this, 'Rule', {
  scheduleExpression: 'rate(5 minutes)',
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
