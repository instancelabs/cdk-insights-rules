import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * opensearch-logging-disabled
 *
 * Audit logs record who queried what; application logs capture errors.
 * Both are off by default.
 */
export const opensearchLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'opensearch-logging-disabled',
    name: 'OpenSearch Logging Disabled',
    description:
      'Detects OpenSearch domains without audit or application logging enabled.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::OpenSearchService::Domain',
      'AWS::Elasticsearch::Domain',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html',
    remediationSteps: [
      'Enable AUDIT_LOGS and ES_APPLICATION_LOGS in LogPublishingOptions',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    const isDisabled = (value: unknown): boolean =>
      !isIntrinsic(value) && asBoolean(value) !== true;

    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type !== 'AWS::OpenSearchService::Domain' &&
        resource.Type !== 'AWS::Elasticsearch::Domain'
      ) {
        continue;
      }
      const options = resource.Properties?.LogPublishingOptions;
      if (isDisabled(options?.AUDIT_LOGS?.Enabled)) {
        report(resourceId, {
          issue: 'OpenSearch domain does not have audit logging enabled.',
          recommendation:
            'Enable AUDIT_LOGS in LogPublishingOptions so user activity is recorded for security monitoring.',
        });
      }
      if (isDisabled(options?.ES_APPLICATION_LOGS?.Enabled)) {
        report(resourceId, {
          issue: 'OpenSearch domain does not have application logging enabled.',
          recommendation:
            'Enable ES_APPLICATION_LOGS in LogPublishingOptions to capture error logs for troubleshooting.',
        });
      }
    }
  },

  example: {
    flagged: `import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';

new opensearch.CfnDomain(this, 'Domain', {
  encryptionAtRestOptions: { enabled: true },
  nodeToNodeEncryptionOptions: { enabled: true },
});`,
    fixed: `import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';

new opensearch.CfnDomain(this, 'Domain', {
  encryptionAtRestOptions: { enabled: true },
  nodeToNodeEncryptionOptions: { enabled: true },
  logPublishingOptions: {
    AUDIT_LOGS: {
      enabled: true,
      cloudWatchLogsLogGroupArn:
        'arn:aws:logs:eu-west-2:111122223333:log-group:/aws/opensearch/audit',
    },
    ES_APPLICATION_LOGS: {
      enabled: true,
      cloudWatchLogsLogGroupArn:
        'arn:aws:logs:eu-west-2:111122223333:log-group:/aws/opensearch/app',
    },
  },
});`,
  },
};
