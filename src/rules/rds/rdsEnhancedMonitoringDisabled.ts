import type { Rule } from '../../types';

const VALID_INTERVALS = new Set([1, 5, 10, 15, 30, 60]);

/**
 * rds-enhanced-monitoring-disabled
 *
 * Standard CloudWatch metrics sample the hypervisor; enhanced monitoring is
 * the OS-level view (per-process CPU, real memory) needed to debug a
 * struggling database.
 */
export const rdsEnhancedMonitoringDisabled: Rule = {
  metadata: {
    ruleId: 'rds-enhanced-monitoring-disabled',
    name: 'RDS Enhanced Monitoring Disabled',
    description:
      'Detects RDS instances without enhanced (OS-level) monitoring.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::RDS::DBInstance'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html',
    remediationSteps: [
      'Set MonitoringInterval (1-60 seconds) and MonitoringRoleArn',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::RDS::DBInstance') {
        continue;
      }
      const raw = resource.Properties?.MonitoringInterval;
      const interval =
        typeof raw === 'number'
          ? raw
          : typeof raw === 'string'
            ? Number.parseInt(raw, 10)
            : undefined;
      if (interval !== undefined && VALID_INTERVALS.has(interval)) {
        continue;
      }
      if (
        raw !== undefined &&
        typeof raw !== 'number' &&
        typeof raw !== 'string'
      ) {
        continue; // intrinsic — undecidable
      }
      report(resourceId, {
        issue: 'RDS instance does not have enhanced monitoring enabled.',
        recommendation:
          'Set MonitoringInterval (e.g. 60) with a MonitoringRoleArn so OS-level metrics are available when the database struggles.',
      });
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
  monitoringInterval: 60,
  monitoringRoleArn:
    'arn:aws:iam::111122223333:role/rds-monitoring-role',
});`,
  },
};
