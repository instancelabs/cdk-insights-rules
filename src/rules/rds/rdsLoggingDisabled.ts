import type { CfnResource, Rule } from '../../types';

const isAuroraMemberInstance = (resource: CfnResource): boolean => {
  const props = resource.Properties ?? {};
  if (props.DBClusterIdentifier !== undefined) {
    return true;
  }
  const engine = props.Engine;
  return (
    typeof engine === 'string' && engine.toLowerCase().startsWith('aurora')
  );
};

/**
 * rds-logging-disabled
 *
 * Without EnableCloudwatchLogsExports, database logs (errors, slow queries,
 * audit) stay on the instance and vanish with it.
 */
export const rdsLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'rds-logging-disabled',
    name: 'RDS Log Exports Disabled',
    description:
      'Detects RDS instances and clusters without CloudWatch log exports.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html',
    remediationSteps: [
      "Set EnableCloudwatchLogsExports for the engine's log types (e.g. error, slowquery, audit)",
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      const isCluster = resource.Type === 'AWS::RDS::DBCluster';
      const isInstance = resource.Type === 'AWS::RDS::DBInstance';
      if (!isCluster && !isInstance) {
        continue;
      }
      if (isInstance && isAuroraMemberInstance(resource)) {
        continue;
      }
      const exports = resource.Properties?.EnableCloudwatchLogsExports;
      if (!Array.isArray(exports) || exports.length === 0) {
        report(resourceId, {
          issue: `RDS ${isCluster ? 'cluster' : 'instance'} does not export logs to CloudWatch.`,
          recommendation:
            'Enable CloudWatch log exports (error/slowquery/audit as the engine supports) so database logs outlive the instance.',
        });
      }
    }
  },

  example: {
    flagged: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
  enableCloudwatchLogsExports: ['error', 'slowquery'],
});`,
  },
};
