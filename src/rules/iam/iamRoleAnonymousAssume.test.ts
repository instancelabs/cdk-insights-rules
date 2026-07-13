import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { iamRoleAnonymousAssume } from './iamRoleAnonymousAssume';

describe('iam-role-anonymous-assume', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [iamRoleAnonymousAssume]);

  const role = (statement: object): CfnTemplate => ({
    Resources: {
      Role: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [statement],
          },
        },
      },
    },
  });

  it('flags wildcard-principal trust with no scoping condition', () => {
    expect(
      run(role({ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }))
    ).toHaveLength(1);
    expect(
      run(
        role({
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag named principals, scoped wildcards, or service trust', () => {
    expect(
      run(
        role({
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::111122223333:root' },
          Action: 'sts:AssumeRole',
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        role({
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
          Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-abc123' } },
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        role({
          Effect: 'Allow',
          Principal: { Service: 'lambda.amazonaws.com' },
          Action: 'sts:AssumeRole',
        })
      )
    ).toHaveLength(0);
  });
});
