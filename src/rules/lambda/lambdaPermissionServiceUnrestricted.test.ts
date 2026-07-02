import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaPermissionServiceUnrestricted } from './lambdaPermissionServiceUnrestricted';

const permission = (properties: object): CfnTemplate => ({
  Resources: {
    Perm: {
      Type: 'AWS::Lambda::Permission',
      Properties: {
        Action: 'lambda:InvokeFunction',
        FunctionName: 'fn',
        ...properties,
      },
    },
  },
});

describe('lambda-permission-service-unrestricted', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaPermissionServiceUnrestricted]);

  it('flags a service principal with no source restriction', () => {
    expect(run(permission({ Principal: 's3.amazonaws.com' }))).toHaveLength(1);
  });

  it('does not flag a service principal with SourceArn or SourceAccount', () => {
    expect(
      run(
        permission({
          Principal: 's3.amazonaws.com',
          SourceArn: 'arn:aws:s3:::my-bucket',
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        permission({
          Principal: 'sns.amazonaws.com',
          SourceAccount: '111122223333',
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag account principals (covered by lambda-permission-public)', () => {
    expect(run(permission({ Principal: '111122223333' }))).toHaveLength(0);
  });
});
