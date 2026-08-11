import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { CfnTemplate, Rule } from '../../types';

/** Return a literal integer, or undefined for unresolved/invalid values. */
const asInteger = (value: unknown): number | undefined => {
  if (isIntrinsic(value)) return undefined;
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value);
  return undefined;
};

const isSnsAction = (value: unknown, template: CfnTemplate): boolean => {
  if (typeof value === 'string') return /^arn:[^:]+:sns:/.test(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;

  const intrinsic = value as Record<string, unknown>;
  const ref = intrinsic.Ref;
  if (typeof ref === 'string') {
    return template.Resources?.[ref]?.Type === 'AWS::SNS::Topic';
  }

  const getAtt = intrinsic['Fn::GetAtt'];
  const logicalId = Array.isArray(getAtt)
    ? getAtt[0]
    : typeof getAtt === 'string'
      ? getAtt.split('.')[0]
      : undefined;
  return (
    typeof logicalId === 'string' &&
    template.Resources?.[logicalId]?.Type === 'AWS::SNS::Topic'
  );
};

const hasSnsAction = (
  properties: Record<string, unknown>,
  template: CfnTemplate
): boolean =>
  ['AlarmActions', 'OKActions', 'InsufficientDataActions'].some((property) => {
    const actions = properties[property];
    return (
      Array.isArray(actions) &&
      actions.some((action) => isSnsAction(action, template))
    );
  });

/**
 * cloudwatch-log-alarm-notification-data-exposure
 *
 * Log alarms can embed raw matching log events in SNS email notifications.
 * AWS warns that those lines might expose sensitive data. The default count
 * is zero, so only an explicit positive literal is actionable here.
 */
export const cloudwatchLogAlarmNotificationDataExposure: Rule = {
  metadata: {
    ruleId: 'cloudwatch-log-alarm-notification-data-exposure',
    name: 'CloudWatch Log Alarm Enables Raw Log Lines In Notifications',
    description:
      'Detects CloudWatch Log Alarms configured to include raw query-result log lines in SNS action notifications.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::CloudWatch::LogAlarm'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-log.html#alarm-log-actions',
    remediationSteps: [
      'Set ActionLogLineCount to 0 unless responders explicitly need raw log events in notifications',
      'If log lines are required, review queried fields for credentials, tokens, personal data, and other sensitive values',
      'Restrict the SNS topic and email subscriptions to the intended incident-response audience',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::CloudWatch::LogAlarm') continue;
      const props = resource.Properties ?? {};
      const count = asInteger(props.ActionLogLineCount);
      if (count === undefined || count <= 0) continue;
      if (
        isIntrinsic(props.ActionsEnabled) ||
        asBoolean(props.ActionsEnabled) === false
      )
        continue;
      if (!hasSnsAction(props, template)) continue;

      report(resourceId, {
        issue: `CloudWatch Log Alarm allows up to ${count} raw log line${count === 1 ? '' : 's'} to be included in SNS email notifications.`,
        recommendation:
          'Set ActionLogLineCount to 0, or confirm the queried logs contain no sensitive data and restrict notification recipients.',
      });
    }
  },

  example: {
    flagged: `import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';

new cloudwatch.CfnLogAlarm(this, 'LogAlarm', {
  actionLogLineCount: 10,
  actionLogLineRoleArn: 'arn:aws:iam::111122223333:role/LogAlarmLines',
  alarmActions: ['arn:aws:sns:eu-west-2:111122223333:oncall'],
  comparisonOperator: 'GreaterThanThreshold',
  queryResultsToAlarm: 1,
  queryResultsToEvaluate: 1,
  scheduledQueryConfiguration: {
    aggregationExpression: 'count(*)',
    logGroupIdentifiers: ['/aws/lambda/orders'],
    queryString: 'fields @message | filter level = "ERROR"',
    scheduleConfiguration: {
      scheduleExpression: 'rate(5 minutes)',
      startTimeOffset: 300,
    },
    scheduledQueryRoleArn: 'arn:aws:iam::111122223333:role/LogAlarmQuery',
  },
  threshold: 1,
});`,
    fixed: `import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';

new cloudwatch.CfnLogAlarm(this, 'LogAlarm', {
  actionLogLineCount: 0,
  alarmActions: ['arn:aws:sns:eu-west-2:111122223333:oncall'],
  comparisonOperator: 'GreaterThanThreshold',
  queryResultsToAlarm: 1,
  queryResultsToEvaluate: 1,
  scheduledQueryConfiguration: {
    aggregationExpression: 'count(*)',
    logGroupIdentifiers: ['/aws/lambda/orders'],
    queryString: 'fields @message | filter level = "ERROR"',
    scheduleConfiguration: {
      scheduleExpression: 'rate(5 minutes)',
      startTimeOffset: 300,
    },
    scheduledQueryRoleArn: 'arn:aws:iam::111122223333:role/LogAlarmQuery',
  },
  threshold: 1,
});`,
  },
};
