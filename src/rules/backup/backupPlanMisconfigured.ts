import type { Rule } from '../../types';

/**
 * backup-plan-misconfigured
 *
 * Two disaster-recovery gaps per backup rule: no cross-region copy (a
 * regional event takes the backups with it) and no lifecycle (backups
 * accumulate forever).
 */
export const backupPlanMisconfigured: Rule = {
  metadata: {
    ruleId: 'backup-plan-misconfigured',
    name: 'Backup Plan Misconfigured',
    description:
      'Detects backup plan rules without cross-region copy or lifecycle configuration.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::Backup::BackupPlan'],
    awsDocUrl:
      'https://docs.aws.amazon.com/aws-backup/latest/devguide/about-backup-plans.html',
    remediationSteps: [
      'Add CopyActions to replicate backups to another region',
      'Set Lifecycle (DeleteAfterDays / MoveToColdStorageAfterDays) on every rule',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Backup::BackupPlan') {
        continue;
      }
      const rules = resource.Properties?.BackupPlan?.BackupPlanRule;
      if (!Array.isArray(rules)) {
        continue;
      }
      for (const planRule of rules) {
        const name = planRule?.RuleName ?? 'unnamed';
        const copyActions = planRule?.CopyActions;
        if (!Array.isArray(copyActions) || copyActions.length === 0) {
          report(resourceId, {
            issue: `Backup rule "${name}" has no cross-region copy configured.`,
            recommendation:
              'Add CopyActions replicating backups to another region so a regional event cannot take primary data and backups together.',
          });
        }
        const lifecycle = planRule?.Lifecycle;
        if (
          !lifecycle?.DeleteAfterDays &&
          !lifecycle?.MoveToColdStorageAfterDays
        ) {
          report(resourceId, {
            issue: `Backup rule "${name}" has no lifecycle configuration.`,
            recommendation:
              'Set DeleteAfterDays or MoveToColdStorageAfterDays so backup storage is managed instead of accumulating forever.',
          });
        }
      }
    }
  },

  example: {
    flagged: `import * as backup from 'aws-cdk-lib/aws-backup';

new backup.CfnBackupPlan(this, 'Plan', {
  backupPlan: {
    backupPlanName: 'daily',
    backupPlanRule: [
      {
        ruleName: 'daily',
        targetBackupVault: 'app-backups',
        scheduleExpression: 'cron(0 3 * * ? *)',
      },
    ],
  },
});`,
    fixed: `import * as backup from 'aws-cdk-lib/aws-backup';

new backup.CfnBackupPlan(this, 'Plan', {
  backupPlan: {
    backupPlanName: 'daily',
    backupPlanRule: [
      {
        ruleName: 'daily',
        targetBackupVault: 'app-backups',
        scheduleExpression: 'cron(0 3 * * ? *)',
        lifecycle: { deleteAfterDays: 35 },
        copyActions: [
          {
            destinationBackupVaultArn:
              'arn:aws:backup:eu-west-1:111122223333:backup-vault:dr-backups',
            lifecycle: { deleteAfterDays: 35 },
          },
        ],
      },
    ],
  },
});`,
  },
};
