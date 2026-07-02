import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { backupPlanMisconfigured } from './backupPlanMisconfigured';

describe('backup-plan-misconfigured', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [backupPlanMisconfigured]);

  const plan = (rules: object[]): CfnTemplate => ({
    Resources: {
      Plan: {
        Type: 'AWS::Backup::BackupPlan',
        Properties: {
          BackupPlan: { BackupPlanName: 'p', BackupPlanRule: rules },
        },
      },
    },
  });

  it('flags a rule with no copy actions and no lifecycle (two findings)', () => {
    expect(
      run(plan([{ RuleName: 'daily', TargetBackupVault: 'v' }]))
    ).toHaveLength(2);
  });

  it('does not flag a rule with cross-region copy and lifecycle', () => {
    expect(
      run(
        plan([
          {
            RuleName: 'daily',
            TargetBackupVault: 'v',
            Lifecycle: { DeleteAfterDays: 35 },
            CopyActions: [{ DestinationBackupVaultArn: 'arn:vault' }],
          },
        ])
      )
    ).toHaveLength(0);
  });
});
