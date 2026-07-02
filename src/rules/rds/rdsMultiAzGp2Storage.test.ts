import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsMultiAzGp2Storage } from './rdsMultiAzGp2Storage';

describe('rds-multi-az-gp2-storage', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsMultiAzGp2Storage]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::RDS::DBInstance', Properties: { ...properties } },
    },
  });

  it('flags Multi-AZ with gp2 or default storage', () => {
    expect(run(res({ MultiAZ: true, StorageType: 'gp2' }))).toHaveLength(1);
    expect(run(res({ MultiAZ: true }))).toHaveLength(1);
  });

  it('does not flag gp3, single-AZ, or io1 instances', () => {
    expect(run(res({ MultiAZ: true, StorageType: 'gp3' }))).toHaveLength(0);
    expect(run(res({ StorageType: 'gp2' }))).toHaveLength(0);
    expect(run(res({ MultiAZ: true, StorageType: 'io1' }))).toHaveLength(0);
  });
});
