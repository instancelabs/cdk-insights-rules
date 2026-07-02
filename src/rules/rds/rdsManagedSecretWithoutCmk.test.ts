import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsManagedSecretWithoutCmk } from './rdsManagedSecretWithoutCmk';

describe('rds-managed-secret-without-cmk', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsManagedSecretWithoutCmk]);

  const db = (properties: object): CfnTemplate => ({
    Resources: {
      Db: { Type: 'AWS::RDS::DBInstance', Properties: properties },
    },
  });

  it('flags a managed secret without a CMK', () => {
    expect(run(db({ ManageMasterUserPassword: true }))).toHaveLength(1);
    expect(run(db({ MasterUserSecret: {} }))).toHaveLength(1);
  });

  it('does not flag a CMK-encrypted secret or unmanaged passwords', () => {
    expect(run(db({ MasterUserSecret: { KmsKeyId: 'arn:key' } }))).toHaveLength(
      0
    );
    expect(run(db({}))).toHaveLength(0);
  });
});
