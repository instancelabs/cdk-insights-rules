import type { Rule } from '../../types';

/**
 * redshift-audit-logging-disabled
 *
 * Without LoggingProperties there is no record of connections, users, or
 * queries against the warehouse.
 */
export const redshiftAuditLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'redshift-audit-logging-disabled',
    name: 'Redshift Audit Logging Disabled',
    description:
      'Detects Redshift clusters without audit logging to S3 or CloudWatch.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Redshift::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html',
    remediationSteps: [
      'Configure LoggingProperties with an S3 bucket, or LogDestinationType cloudwatch with LogExports',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Redshift::Cluster') {
        continue;
      }
      const logging = resource.Properties?.LoggingProperties;
      const usesS3 = Boolean(logging?.BucketName);
      const usesCloudWatch =
        logging?.LogDestinationType === 'cloudwatch' ||
        (Array.isArray(logging?.LogExports) && logging.LogExports.length > 0);
      if (!usesS3 && !usesCloudWatch) {
        report(resourceId, {
          issue: 'Redshift cluster does not have audit logging enabled.',
          recommendation:
            'Configure LoggingProperties so connection, user, and query activity is recorded for audit.',
        });
      }
    }
  },

  example: {
    flagged: `import * as redshift from 'aws-cdk-lib/aws-redshift';

new redshift.CfnCluster(this, 'Cluster', {
  clusterType: 'single-node',
  dbName: 'analytics',
  masterUsername: 'admin',
  masterUserPassword: 'example-Password1',
  nodeType: 'dc2.large',
  encrypted: true,
});`,
    fixed: `import * as redshift from 'aws-cdk-lib/aws-redshift';

new redshift.CfnCluster(this, 'Cluster', {
  clusterType: 'single-node',
  dbName: 'analytics',
  masterUsername: 'admin',
  masterUserPassword: 'example-Password1',
  nodeType: 'dc2.large',
  encrypted: true,
  loggingProperties: {
    bucketName: 'my-redshift-audit-logs',
  },
});`,
  },
};
