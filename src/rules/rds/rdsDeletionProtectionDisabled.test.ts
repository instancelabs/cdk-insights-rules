import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsDeletionProtectionDisabled } from './rdsDeletionProtectionDisabled';

describe('rds-deletion-protection-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsDeletionProtectionDisabled]);

  it('flags instances and clusters without deletion protection', () => {
    expect(
      run({
        Resources: {
          Db: { Type: 'AWS::RDS::DBInstance', Properties: { Engine: 'mysql' } },
          Cluster: { Type: 'AWS::RDS::DBCluster', Properties: {} },
        },
      })
    ).toHaveLength(2);
  });

  it('does not flag protected databases or Aurora member instances', () => {
    expect(
      run({
        Resources: {
          Db: {
            Type: 'AWS::RDS::DBInstance',
            Properties: { Engine: 'mysql', DeletionProtection: true },
          },
          Member: {
            Type: 'AWS::RDS::DBInstance',
            Properties: {
              Engine: 'aurora-mysql',
              DBClusterIdentifier: { Ref: 'Cluster' },
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
