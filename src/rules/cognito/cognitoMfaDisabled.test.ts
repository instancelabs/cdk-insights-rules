import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cognitoMfaDisabled } from './cognitoMfaDisabled';

describe('cognito-mfa-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cognitoMfaDisabled]);

  const pool = (properties: object): CfnTemplate => ({
    Resources: {
      Pool: { Type: 'AWS::Cognito::UserPool', Properties: properties },
    },
  });

  it('flags MFA off or unset', () => {
    expect(run(pool({}))).toHaveLength(1);
    expect(run(pool({ MfaConfiguration: 'OFF' }))).toHaveLength(1);
  });

  it('does not flag ON or OPTIONAL', () => {
    expect(run(pool({ MfaConfiguration: 'ON' }))).toHaveLength(0);
    expect(run(pool({ MfaConfiguration: 'OPTIONAL' }))).toHaveLength(0);
  });
});
