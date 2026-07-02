import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { backupVaultHardening } from './backupVaultHardening';

describe('backup-vault-hardening', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [backupVaultHardening]);

  it('flags a vault with no CMK and no lock (two findings)', () => {
    expect(
      run({
        Resources: {
          Vault: {
            Type: 'AWS::Backup::BackupVault',
            Properties: { BackupVaultName: 'v' },
          },
        },
      })
    ).toHaveLength(2);
  });

  it('recognizes an inline lock and a separate BackupVaultLock (by Ref)', () => {
    expect(
      run({
        Resources: {
          Vault: {
            Type: 'AWS::Backup::BackupVault',
            Properties: {
              BackupVaultName: 'v',
              EncryptionKeyArn: 'arn:key',
              LockConfiguration: { MinRetentionDays: 30 },
            },
          },
        },
      })
    ).toHaveLength(0);
    expect(
      run({
        Resources: {
          Vault: {
            Type: 'AWS::Backup::BackupVault',
            Properties: { BackupVaultName: 'v', EncryptionKeyArn: 'arn:key' },
          },
          Lock: {
            Type: 'AWS::Backup::BackupVaultLock',
            Properties: {
              BackupVaultName: { Ref: 'Vault' },
              MinRetentionDays: 30,
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
