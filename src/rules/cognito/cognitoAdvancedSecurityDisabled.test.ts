import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cognitoAdvancedSecurityDisabled } from './cognitoAdvancedSecurityDisabled';

describe('cognito-advanced-security-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cognitoAdvancedSecurityDisabled]);

  const pool = (properties: object): CfnTemplate => ({
    Resources: {
      Pool: { Type: 'AWS::Cognito::UserPool', Properties: properties },
    },
  });

  it('flags OFF or unset advanced security', () => {
    expect(run(pool({}))).toHaveLength(1);
    expect(
      run(pool({ UserPoolAddOns: { AdvancedSecurityMode: 'OFF' } }))
    ).toHaveLength(1);
  });

  it('does not flag AUDIT or ENFORCED', () => {
    expect(
      run(pool({ UserPoolAddOns: { AdvancedSecurityMode: 'AUDIT' } }))
    ).toHaveLength(0);
    expect(
      run(pool({ UserPoolAddOns: { AdvancedSecurityMode: 'ENFORCED' } }))
    ).toHaveLength(0);
  });
});
