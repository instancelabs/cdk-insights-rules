import { isCdkInternalLogicalId } from '../../cfn.js';
import type { CfnResource, Rule } from '../../types';

/** Service principals that invoke Lambda asynchronously. */
const ASYNC_PRINCIPALS = new Set([
  'events.amazonaws.com',
  'sns.amazonaws.com',
  's3.amazonaws.com',
  'ses.amazonaws.com',
  'codecommit.amazonaws.com',
  'codepipeline.amazonaws.com',
  'config.amazonaws.com',
  'cloudwatch.amazonaws.com',
  'iot.amazonaws.com',
  'logs.amazonaws.com',
  'pipes.amazonaws.com',
  'scheduler.amazonaws.com',
  'cognito-idp.amazonaws.com',
]);

const functionRefOf = (functionName: unknown): string | undefined => {
  if (typeof functionName === 'string') {
    return functionName;
  }
  if (functionName && typeof functionName === 'object') {
    const obj = functionName as Record<string, unknown>;
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

interface InvocationInfo {
  asyncInvoked: Set<string>;
  eventSourceOnly: Set<string>;
  asyncFailureHandled: Set<string>;
}

const detectInvocations = (
  resources: Record<string, CfnResource>
): InvocationInfo => {
  const asyncInvoked = new Set<string>();
  const eventSource = new Set<string>();
  const asyncFailureHandled = new Set<string>();
  for (const resource of Object.values(resources)) {
    if (resource.Type === 'AWS::Lambda::Permission') {
      const fn = functionRefOf(resource.Properties?.FunctionName);
      const principal = resource.Properties?.Principal;
      if (
        fn &&
        typeof principal === 'string' &&
        ASYNC_PRINCIPALS.has(principal)
      ) {
        asyncInvoked.add(fn);
      }
    } else if (resource.Type === 'AWS::Lambda::EventSourceMapping') {
      const fn = functionRefOf(resource.Properties?.FunctionName);
      if (fn) {
        eventSource.add(fn);
      }
    } else if (resource.Type === 'AWS::Lambda::EventInvokeConfig') {
      const fn = functionRefOf(resource.Properties?.FunctionName);
      if (fn) {
        asyncInvoked.add(fn);
        if (resource.Properties?.DestinationConfig?.OnFailure?.Destination) {
          asyncFailureHandled.add(fn);
        }
      }
    }
  }
  const eventSourceOnly = new Set(
    [...eventSource].filter((fn) => !asyncInvoked.has(fn))
  );
  return { asyncInvoked, eventSourceOnly, asyncFailureHandled };
};

/**
 * lambda-dlq-missing
 *
 * Async-invoked functions (EventBridge, SNS, S3, ...) drop the event after
 * retries unless a DeadLetterConfig or an EventInvokeConfig OnFailure
 * destination captures it. Poll-based sources (SQS/Kinesis) need an
 * OnFailure destination on the EventSourceMapping instead. Functions whose
 * invocation mode cannot be inferred from the template are NOT flagged —
 * they may be sync-invoked from another stack. (The product flags those as
 * "unknown"; the open rule stays conservative.)
 */
export const lambdaDlqMissing: Rule = {
  metadata: {
    ruleId: 'lambda-dlq-missing',
    name: 'Lambda DLQ Missing',
    description:
      'Detects async-invoked Lambda functions without a dead-letter queue or failure destination.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::Lambda::Function'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-dlq',
    remediationSteps: [
      'Configure DeadLetterConfig (SQS/SNS) or an EventInvokeConfig OnFailure destination for async-invoked functions',
      'For SQS/Kinesis event sources, set DestinationConfig.OnFailure on the EventSourceMapping',
    ],
  },

  check: (template, report) => {
    const resources = template.Resources ?? {};
    const { asyncInvoked, eventSourceOnly, asyncFailureHandled } =
      detectInvocations(resources);

    for (const [resourceId, resource] of Object.entries(resources)) {
      if (resource.Type !== 'AWS::Lambda::Function') {
        continue;
      }
      if (isCdkInternalLogicalId(resourceId)) {
        continue;
      }
      if (resource.Properties?.DeadLetterConfig?.TargetArn) {
        continue;
      }
      if (
        asyncInvoked.has(resourceId) &&
        !asyncFailureHandled.has(resourceId)
      ) {
        report(resourceId, {
          issue:
            'Async-invoked Lambda function has no dead-letter queue or failure destination.',
          recommendation:
            'Configure DeadLetterConfig or an EventInvokeConfig OnFailure destination so failed async events are captured instead of dropped after retries.',
        });
      } else if (eventSourceOnly.has(resourceId)) {
        report(resourceId, {
          issue:
            'Lambda function consumes an event source mapping without a failure destination.',
          recommendation:
            'Set DestinationConfig.OnFailure on the EventSourceMapping — function-level DLQs do not apply to poll-based sources like SQS/Kinesis.',
        });
      }
    }
  },

  example: {
    flagged: `import * as lambda from 'aws-cdk-lib/aws-lambda';

const fn = new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
});
new lambda.CfnPermission(this, 'EventsPermission', {
  action: 'lambda:InvokeFunction',
  functionName: fn.ref,
  principal: 'events.amazonaws.com',
  sourceArn: 'arn:aws:events:eu-west-2:111122223333:rule/tick',
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

const fn = new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
  deadLetterConfig: {
    targetArn: 'arn:aws:sqs:eu-west-2:111122223333:fn-dlq',
  },
});
new lambda.CfnPermission(this, 'EventsPermission', {
  action: 'lambda:InvokeFunction',
  functionName: fn.ref,
  principal: 'events.amazonaws.com',
  sourceArn: 'arn:aws:events:eu-west-2:111122223333:rule/tick',
});`,
  },
};
