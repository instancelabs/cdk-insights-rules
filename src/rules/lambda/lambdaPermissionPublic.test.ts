import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaPermissionPublic } from './lambdaPermissionPublic';

describe('lambda-permission-public', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaPermissionPublic]);

  it('flags a permission with a wildcard principal and no restriction', () => {
    expect(
      run({
        Resources: {
          Perm: {
            Type: 'AWS::Lambda::Permission',
            Properties: {
              Action: 'lambda:InvokeFunction',
              FunctionName: 'fn',
              Principal: '*',
            },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('flags a layer-version permission with a wildcard principal', () => {
    expect(
      run({
        Resources: {
          LayerPerm: {
            Type: 'AWS::Lambda::LayerVersionPermission',
            Properties: {
              Action: 'lambda:GetLayerVersion',
              LayerVersionArn: 'arn:aws:lambda:eu-west-2:1:layer:l:1',
              Principal: '*',
            },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag a wildcard principal scoped by a source restriction', () => {
    expect(
      run({
        Resources: {
          Perm: {
            Type: 'AWS::Lambda::Permission',
            Properties: {
              Action: 'lambda:InvokeFunction',
              FunctionName: 'fn',
              Principal: '*',
              PrincipalOrgID: 'o-abc123',
            },
          },
          LayerPerm: {
            Type: 'AWS::Lambda::LayerVersionPermission',
            Properties: {
              Action: 'lambda:GetLayerVersion',
              LayerVersionArn: 'arn:aws:lambda:eu-west-2:1:layer:l:1',
              Principal: '*',
              OrganizationId: 'o-abc123',
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag account or service principals', () => {
    expect(
      run({
        Resources: {
          Account: {
            Type: 'AWS::Lambda::Permission',
            Properties: {
              Action: 'lambda:InvokeFunction',
              FunctionName: 'fn',
              Principal: '111122223333',
            },
          },
          Service: {
            Type: 'AWS::Lambda::Permission',
            Properties: {
              Action: 'lambda:InvokeFunction',
              FunctionName: 'fn',
              Principal: 's3.amazonaws.com',
              SourceAccount: '111122223333',
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
