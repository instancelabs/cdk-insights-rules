import type { Rule } from '../../types';

/**
 * Resolve the logical id a dead-letter-target ARN points at.
 *
 * The ARN is normally an intrinsic: `{ 'Fn::GetAtt': ['SomeId', 'Arn'] }`
 * (take element [0]) or `{ Ref: 'SomeId' }` (take the Ref). Plain strings and
 * anything unrecognized resolve to `undefined`.
 */
const resolveLogicalId = (arn: unknown): string | undefined => {
  if (!arn || typeof arn !== 'object') {
    return undefined;
  }
  const intrinsic = arn as Record<string, unknown>;
  const getAtt = intrinsic['Fn::GetAtt'];
  if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') {
    return getAtt[0];
  }
  if (typeof intrinsic.Ref === 'string') {
    return intrinsic.Ref;
  }
  return undefined;
};

/**
 * sqs-queue-no-dlq — flag queues without a dead-letter queue.
 *
 * A queue with no RedrivePolicy silently loses messages that repeatedly fail
 * processing. Two passes: first collect the queues that are themselves used as
 * dead-letter targets (so we never flag a DLQ for lacking its own DLQ), then
 * report every queue that has no RedrivePolicy and isn't a DLQ.
 */
export const sqsQueueNoDlq: Rule = {
  metadata: {
    ruleId: 'sqs-queue-no-dlq',
    name: 'SQS Queue Without Dead-Letter Queue',
    description:
      'Detects SQS queues with no RedrivePolicy, so messages that repeatedly fail processing are lost instead of captured for inspection.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::SQS::Queue'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html',
    remediationSteps: [
      'Add a RedrivePolicy pointing at a dead-letter queue with a sensible maxReceiveCount',
      'Alarm on the dead-letter queue depth so poison messages are noticed',
    ],
    complianceFrameworks: ['SOC2'],
  },

  check: (template, report) => {
    const entries = Object.entries(template.Resources ?? {});

    // Pass 1 — logical ids used AS dead-letter queues.
    const deadLetterIds = new Set<string>();
    for (const [, resource] of entries) {
      if (resource.Type !== 'AWS::SQS::Queue') {
        continue;
      }
      const targetArn = resource.Properties?.RedrivePolicy?.deadLetterTargetArn;
      const targetId = resolveLogicalId(targetArn);
      if (targetId) {
        deadLetterIds.add(targetId);
      }
    }

    // Pass 2 — queues with no RedrivePolicy that aren't themselves a DLQ.
    for (const [resourceId, resource] of entries) {
      if (resource.Type !== 'AWS::SQS::Queue') {
        continue;
      }
      if (resource.Properties?.RedrivePolicy || deadLetterIds.has(resourceId)) {
        continue;
      }
      report(resourceId, {
        issue:
          'SQS queue has no dead-letter queue configured (no RedrivePolicy).',
        recommendation:
          'Attach a RedrivePolicy pointing at a dead-letter queue so messages that repeatedly fail processing are captured for inspection instead of being lost.',
      });
    }
  },

  example: {
    flagged: `import * as sqs from 'aws-cdk-lib/aws-sqs';

new sqs.CfnQueue(this, 'Queue', {});`,
    fixed: `import * as sqs from 'aws-cdk-lib/aws-sqs';

const dlq = new sqs.CfnQueue(this, 'Dlq', {});

new sqs.CfnQueue(this, 'Queue', {
  redrivePolicy: {
    deadLetterTargetArn: dlq.attrArn,
    maxReceiveCount: 5,
  },
});`,
  },
};
