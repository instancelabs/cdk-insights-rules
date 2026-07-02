import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsEncryptionDisabled } from './rdsEncryptionDisabled';

describe('rds-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsEncryptionDisabled]).map(
      (finding) => finding.resourceId
    );

  it('flags an unencrypted DB instance', () => {
    expect(
      run({
        Resources: {
          Db: {
            Type: 'AWS::RDS::DBInstance',
            Properties: { Engine: 'mysql' },
          },
        },
      })
    ).toEqual(['Db']);
  });

  it('flags an unencrypted DB cluster', () => {
    expect(
      run({
        Resources: {
          Cluster: {
            Type: 'AWS::RDS::DBCluster',
            Properties: { Engine: 'aurora-postgresql' },
          },
        },
      })
    ).toEqual(['Cluster']);
  });

  it('does not flag an Aurora member instance (cluster carries encryption)', () => {
    expect(
      run({
        Resources: {
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

  it('does not flag StorageEncrypted true (boolean or string form)', () => {
    expect(
      run({
        Resources: {
          Db: {
            Type: 'AWS::RDS::DBInstance',
            Properties: { Engine: 'mysql', StorageEncrypted: true },
          },
          Db2: {
            Type: 'AWS::RDS::DBInstance',
            Properties: { Engine: 'mysql', StorageEncrypted: 'true' },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag StorageEncrypted set via an intrinsic (undecidable)', () => {
    expect(
      run({
        Resources: {
          Db: {
            Type: 'AWS::RDS::DBInstance',
            Properties: {
              Engine: 'mysql',
              StorageEncrypted: { 'Fn::If': ['Prod', true, false] },
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
