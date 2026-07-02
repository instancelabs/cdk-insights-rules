import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsLoggingDisabled } from './rdsLoggingDisabled';

describe('rds-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsLoggingDisabled]);

  it('flags instances and clusters without log exports', () => {
    expect(
      run({
        Resources: {
          Db: { Type: 'AWS::RDS::DBInstance', Properties: { Engine: 'mysql' } },
          Cluster: { Type: 'AWS::RDS::DBCluster', Properties: {} },
        },
      })
    ).toHaveLength(2);
  });

  it('does not flag exported logs or Aurora member instances', () => {
    expect(
      run({
        Resources: {
          Db: {
            Type: 'AWS::RDS::DBInstance',
            Properties: {
              Engine: 'mysql',
              EnableCloudwatchLogsExports: ['error'],
            },
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
