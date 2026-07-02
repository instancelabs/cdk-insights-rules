import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { iamPermissionBoundaryMissing } from './iamPermissionBoundaryMissing';

describe('iam-permission-boundary-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [iamPermissionBoundaryMissing]);

  const role = (principal: object, extra: object = {}): CfnTemplate => ({
    Resources: {
      Role: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: principal,
                Action: 'sts:AssumeRole',
              },
            ],
          },
          ...extra,
        },
      },
    },
  });

  it('flags AWS-principal roles without a boundary', () => {
    expect(run(role({ AWS: 'arn:aws:iam::111122223333:root' }))).toHaveLength(
      1
    );
  });

  it('does not flag service roles (the CDK-generated majority)', () => {
    expect(run(role({ Service: 'lambda.amazonaws.com' }))).toHaveLength(0);
  });

  it('does not flag roles with a boundary', () => {
    expect(
      run(
        role(
          { AWS: 'arn:aws:iam::111122223333:root' },
          { PermissionsBoundary: 'arn:aws:iam::111122223333:policy/boundary' }
        )
      )
    ).toHaveLength(0);
  });
});
