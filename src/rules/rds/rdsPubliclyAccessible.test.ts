import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsPubliclyAccessible } from './rdsPubliclyAccessible';

describe('rds-publicly-accessible', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsPubliclyAccessible]);

  it('flags a publicly accessible DB instance', () => {
    expect(
      run({
        Resources: {
          Db: {
            Type: 'AWS::RDS::DBInstance',
            Properties: { PubliclyAccessible: true },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('flags the CloudFormation string form "true"', () => {
    expect(
      run({
        Resources: {
          Db: {
            Type: 'AWS::RDS::DBInstance',
            Properties: { PubliclyAccessible: 'true' },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag a private instance (false, absent, or intrinsic)', () => {
    expect(
      run({
        Resources: {
          Private: {
            Type: 'AWS::RDS::DBInstance',
            Properties: { PubliclyAccessible: false },
          },
          Default: { Type: 'AWS::RDS::DBInstance', Properties: {} },
          Conditional: {
            Type: 'AWS::RDS::DBInstance',
            Properties: {
              PubliclyAccessible: { 'Fn::If': ['Dev', true, false] },
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
