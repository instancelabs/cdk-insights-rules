import type { Rule } from '../../types';

/**
 * rds-backup-retention-low
 *
 * BackupRetentionPeriod 0 disables automated backups entirely; anything
 * under 7 days is a thin window for point-in-time recovery. Cluster default
 * (unset) is 1 day and counts as low; instance default is also 1 day but the
 * product leaves unset instances unflagged — parity preserved.
 */
export const rdsBackupRetentionLow: Rule = {
  metadata: {
    ruleId: 'rds-backup-retention-low',
    name: 'RDS Backup Retention Low',
    description:
      'Detects RDS instances and clusters with automated backups disabled or retention under 7 days.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
    remediationSteps: [
      'Set BackupRetentionPeriod to at least 7 for production databases',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
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
      const raw = resource.Properties?.BackupRetentionPeriod;
      // Clusters default to 1 day when unset; treat as such.
      const retention =
        isCluster && raw === undefined
          ? 1
          : typeof raw === 'number'
            ? raw
            : undefined;
      const noun = isCluster ? 'cluster' : 'instance';
      if (retention === 0) {
        report(resourceId, {
          issue: `RDS ${noun} has automated backups disabled (BackupRetentionPeriod is 0).`,
          recommendation:
            'Enable automated backups with at least 7 days retention so point-in-time recovery is possible.',
        });
      } else if (retention !== undefined && retention < 7) {
        report(resourceId, {
          issue: `RDS ${noun} backup retention is only ${retention} day(s).`,
          recommendation:
            'Increase BackupRetentionPeriod to at least 7 days for production databases.',
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
  backupRetentionPeriod: 1,
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
  backupRetentionPeriod: 14,
});`,
  },
};
