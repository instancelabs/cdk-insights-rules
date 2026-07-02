import type { Rule } from '../../types';

/**
 * cloudwatch-logs-encryption-disabled
 *
 * Log groups are encrypted at rest by CloudWatch by default; a customer-
 * managed key adds key-policy control and audit for sensitive log data.
 * Advisory (LOW).
 */
export const cloudwatchLogsEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'cloudwatch-logs-encryption-disabled',
    name: 'CloudWatch Logs Without Customer-Managed Key',
    description:
      'Detects CloudWatch log groups without a customer-managed KMS key.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Logs::LogGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html',
    remediationSteps: [
      'Set KmsKeyId on log groups holding sensitive data (in CDK: encryptionKey)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::Logs::LogGroup' &&
        !resource.Properties?.KmsKeyId
      ) {
        report(resourceId, {
          issue:
            'CloudWatch log group is not encrypted with a customer-managed KMS key.',
          recommendation:
            'Set KmsKeyId for log groups that hold sensitive data so encryption is controlled and auditable via your key policy.',
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
  kmsKeyId:
    'arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
});`,
  },
};
