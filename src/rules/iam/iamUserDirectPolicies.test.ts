import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { iamUserDirectPolicies } from './iamUserDirectPolicies';

describe('iam-user-direct-policies', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [iamUserDirectPolicies]);

  const user = (properties: object): CfnTemplate => ({
    Resources: {
      User: { Type: 'AWS::IAM::User', Properties: properties },
    },
  });

  it('flags inline and managed policies attached directly', () => {
    expect(
      run(user({ Policies: [{ PolicyName: 'p', PolicyDocument: {} }] }))
    ).toHaveLength(1);
    expect(
      run(user({ ManagedPolicyArns: ['arn:aws:iam::aws:policy/ReadOnly'] }))
    ).toHaveLength(1);
  });

  it('does not flag a user with only group membership', () => {
    expect(run(user({ Groups: ['developers'] }))).toHaveLength(0);
    expect(run(user({}))).toHaveLength(0);
  });
});
