import type { Rule } from '../../types';

/**
 * backup-vault-hardening
 *
 * Two hardening signals for backup vaults: a customer-managed encryption
 * key, and a vault lock (inline LockConfiguration or a separate
 * BackupVaultLock resource) so backups can't be deleted — the ransomware
 * defence.
 */
export const backupVaultHardening: Rule = {
  metadata: {
    ruleId: 'backup-vault-hardening',
    name: 'Backup Vault Hardening',
    description:
      'Detects backup vaults without a customer-managed KMS key or without a vault lock.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Backup::BackupVault', 'AWS::Backup::BackupVaultLock'],
    awsDocUrl:
      'https://docs.aws.amazon.com/aws-backup/latest/devguide/vaultlock.html',
    remediationSteps: [
      'Set EncryptionKeyArn to a customer-managed KMS key',
      'Add a LockConfiguration (or AWS::Backup::BackupVaultLock) so backups cannot be deleted before their retention period',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
  },

  check: (template, report) => {
    const entries = Object.entries(template.Resources ?? {});

    const lockedVaultNames = new Set<string>();
    for (const [, resource] of entries) {
      if (resource.Type !== 'AWS::Backup::BackupVaultLock') {
        continue;
      }
      const vaultName = resource.Properties?.BackupVaultName;
      if (typeof vaultName === 'string') {
        lockedVaultNames.add(vaultName);
      } else if (typeof vaultName?.Ref === 'string') {
        lockedVaultNames.add(vaultName.Ref);
      }
    }

    for (const [resourceId, resource] of entries) {
      if (resource.Type !== 'AWS::Backup::BackupVault') {
        continue;
      }
      const props = resource.Properties ?? {};
      if (!props.EncryptionKeyArn) {
        report(resourceId, {
          issue: 'Backup vault uses the default AWS-managed encryption key.',
          recommendation:
            'Set EncryptionKeyArn to a customer-managed KMS key for control over backup encryption.',
        });
      }
      const vaultName =
        typeof props.BackupVaultName === 'string'
          ? props.BackupVaultName
          : props.BackupVaultName?.Ref;
      const locked =
        Boolean(props.LockConfiguration) ||
        lockedVaultNames.has(resourceId) ||
        (typeof vaultName === 'string' && lockedVaultNames.has(vaultName));
      if (!locked) {
        report(resourceId, {
          issue: 'Backup vault has no vault lock configured.',
          recommendation:
            'Add a LockConfiguration (or BackupVaultLock) so backups cannot be deleted before retention expires — the core ransomware defence for backups.',
        });
      }
    }
  },

  example: {
    flagged: `import * as backup from 'aws-cdk-lib/aws-backup';

new backup.CfnBackupVault(this, 'Vault', {
  backupVaultName: 'app-backups',
});`,
    fixed: `import * as backup from 'aws-cdk-lib/aws-backup';

new backup.CfnBackupVault(this, 'Vault', {
  backupVaultName: 'app-backups',
  encryptionKeyArn:
    'arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  lockConfiguration: {
    minRetentionDays: 30,
  },
});`,
  },
};
