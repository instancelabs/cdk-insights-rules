import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsBackupRetentionLow } from './rdsBackupRetentionLow';

describe('rds-backup-retention-low', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsBackupRetentionLow]);

  const db = (type: string, properties: object): CfnTemplate => ({
    Resources: {
      Db: { Type: type, Properties: properties },
    },
  });

  it('flags disabled backups and low retention', () => {
    const disabled = run(
      db('AWS::RDS::DBInstance', { BackupRetentionPeriod: 0 })
    );
    expect(disabled).toHaveLength(1);
    expect(disabled[0].issue).toContain('disabled');
    expect(
      run(db('AWS::RDS::DBInstance', { BackupRetentionPeriod: 3 }))
    ).toHaveLength(1);
  });

  it('treats an unset cluster as the 1-day default (flagged), unset instance as unflagged', () => {
    expect(run(db('AWS::RDS::DBCluster', {}))).toHaveLength(1);
    expect(run(db('AWS::RDS::DBInstance', {}))).toHaveLength(0);
  });

  it('does not flag retention of 7+ or intrinsic values', () => {
    expect(
      run(db('AWS::RDS::DBInstance', { BackupRetentionPeriod: 7 }))
    ).toHaveLength(0);
    expect(
      run(
        db('AWS::RDS::DBInstance', {
          BackupRetentionPeriod: { 'Fn::If': ['P', 14, 1] },
        })
      )
    ).toHaveLength(0);
  });
});
