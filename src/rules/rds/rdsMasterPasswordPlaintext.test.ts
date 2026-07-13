import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsMasterPasswordPlaintext } from './rdsMasterPasswordPlaintext';

describe('rds-master-password-plaintext', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsMasterPasswordPlaintext]);

  const db = (
    password: unknown,
    type = 'AWS::RDS::DBInstance'
  ): CfnTemplate => ({
    Resources: {
      Db: {
        Type: type,
        Properties: {
          Engine: 'postgres',
          ...(password === undefined ? {} : { MasterUserPassword: password }),
        },
      },
    },
  });

  it('flags a literal password on instances and clusters', () => {
    expect(run(db('SuperSecretPassw0rd!'))).toHaveLength(1);
    expect(run(db('SuperSecretPassw0rd!', 'AWS::RDS::DBCluster'))).toHaveLength(
      1
    );
  });

  it('does not flag dynamic references, intrinsics, or managed credentials', () => {
    expect(
      run(db('{{resolve:secretsmanager:my-secret:SecretString:password}}'))
    ).toHaveLength(0);
    expect(run(db({ Ref: 'DbPasswordParameter' }))).toHaveLength(0);
    expect(
      run(db({ 'Fn::Join': ['', ['{{resolve:ssm-secure:/db/pw:1}}']] }))
    ).toHaveLength(0);
    expect(run(db(undefined))).toHaveLength(0);
  });
});
