import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cognitoPasswordPolicyWeak } from './cognitoPasswordPolicyWeak';

const userPool = (properties: object): CfnTemplate => ({
  Resources: {
    Pool: { Type: 'AWS::Cognito::UserPool', Properties: properties },
  },
});

describe('cognito-password-policy-weak', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cognitoPasswordPolicyWeak]);

  it('flags a pool with no password policy', () => {
    expect(run(userPool({}))).toHaveLength(1);
  });

  it('flags a minimum length below 12', () => {
    expect(
      run(userPool({ Policies: { PasswordPolicy: { MinimumLength: 8 } } }))
    ).toHaveLength(1);
  });

  it('does not flag a strong policy', () => {
    expect(
      run(userPool({ Policies: { PasswordPolicy: { MinimumLength: 14 } } }))
    ).toHaveLength(0);
  });
});
