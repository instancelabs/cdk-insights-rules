import type { Rule } from '../../types';

/**
 * cloudwatch-logs-retention-missing
 *
 * A log group without RetentionInDays keeps every byte forever — the classic
 * slow-burn CloudWatch bill.
 */
export const cloudwatchLogsRetentionMissing: Rule = {
  metadata: {
    ruleId: 'cloudwatch-logs-retention-missing',
    name: 'CloudWatch Logs Retention Missing',
    description:
      'Detects CloudWatch log groups without a retention period (logs kept forever).',
    severity: 'MEDIUM',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::Logs::LogGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html',
    remediationSteps: [
      'Set RetentionInDays (30-90 days for operational logs; longer where compliance requires)',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::Logs::LogGroup' &&
        resource.Properties?.RetentionInDays === undefined
      ) {
        report(resourceId, {
          issue:
            'CloudWatch log group has no retention period — logs are kept (and billed) forever.',
          recommendation:
            'Set RetentionInDays so storage is bounded; 30-90 days suits most operational logs.',
        });
      }
    }
  },

  example: {
    flagged: `import * as logs from 'aws-cdk-lib/aws-logs';

new logs.CfnLogGroup(this, 'LogGroup', {
  logGroupName: '/app/api',
});`,
    fixed: `import * as logs from 'aws-cdk-lib/aws-logs';

new logs.CfnLogGroup(this, 'LogGroup', {
  logGroupName: '/app/api',
  retentionInDays: 90,
});`,
  },
};
