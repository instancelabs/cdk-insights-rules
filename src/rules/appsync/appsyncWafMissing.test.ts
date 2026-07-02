import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { appsyncWafMissing } from './appsyncWafMissing';

describe('appsync-waf-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [appsyncWafMissing]);

  const apiResource = {
    Type: 'AWS::AppSync::GraphQLApi',
    Properties: { Name: 'api', AuthenticationType: 'AWS_IAM' },
  };

  it('flags an API with no WAF association', () => {
    expect(run({ Resources: { Api: apiResource } })).toHaveLength(1);
  });

  it('does not flag an API referenced by an association (GetAtt or Sub)', () => {
    expect(
      run({
        Resources: {
          Api: apiResource,
          Assoc: {
            Type: 'AWS::WAFv2::WebACLAssociation',
            Properties: {
              ResourceArn: { 'Fn::GetAtt': ['Api', 'Arn'] },
              WebAclArn: 'arn:acl',
            },
          },
        },
      })
    ).toHaveLength(0);
    expect(
      run({
        Resources: {
          Api: apiResource,
          Assoc: {
            Type: 'AWS::WAFv2::WebACLAssociation',
            Properties: {
              ResourceArn: { 'Fn::Sub': '${Api.Arn}' },
              WebAclArn: 'arn:acl',
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
