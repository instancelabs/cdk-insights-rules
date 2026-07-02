import type { Rule } from '../../types';

/**
 * cloudwatch-alarm-actions-missing
 *
 * An alarm with no actions changes colour on a dashboard nobody watches;
 * unspecified missing-data handling makes alarm behaviour ambiguous during
 * gaps.
 */
export const cloudwatchAlarmActionsMissing: Rule = {
  metadata: {
    ruleId: 'cloudwatch-alarm-actions-missing',
    name: 'CloudWatch Alarm Actions Missing',
    description:
      'Detects CloudWatch alarms without alarm actions or missing-data handling.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::CloudWatch::Alarm'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html',
    remediationSteps: [
      'Add AlarmActions (an SNS topic feeding your paging/chat tooling)',
      'Set TreatMissingData explicitly (missing, ignore, breaching, or notBreaching)',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::CloudWatch::Alarm') {
        continue;
      }
      const props = resource.Properties ?? {};
      const actions = props.AlarmActions;
      if (!Array.isArray(actions) || actions.length === 0) {
        report(resourceId, {
          issue: 'CloudWatch alarm has no alarm actions configured.',
          recommendation:
            'Add AlarmActions (e.g. an SNS topic) so the alarm notifies someone instead of only changing state.',
        });
      }
      if (!props.TreatMissingData) {
        report(resourceId, {
          issue: 'CloudWatch alarm does not specify how to treat missing data.',
          recommendation:
            'Set TreatMissingData so behaviour during metric gaps is deliberate rather than the default.',
        });
      }
    }
  },

  example: {
    flagged: `import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';

new cloudwatch.CfnAlarm(this, 'Alarm', {
  comparisonOperator: 'GreaterThanThreshold',
  evaluationPeriods: 3,
  metricName: 'Errors',
  namespace: 'AWS/Lambda',
  period: 60,
  statistic: 'Sum',
  threshold: 5,
});`,
    fixed: `import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';

new cloudwatch.CfnAlarm(this, 'Alarm', {
  comparisonOperator: 'GreaterThanThreshold',
  evaluationPeriods: 3,
  metricName: 'Errors',
  namespace: 'AWS/Lambda',
  period: 60,
  statistic: 'Sum',
  threshold: 5,
  treatMissingData: 'notBreaching',
  alarmActions: ['arn:aws:sns:eu-west-2:111122223333:oncall'],
});`,
  },
};
