import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { apigatewayDefaultEndpointEnabled } from './apigatewayDefaultEndpointEnabled';

describe('apigateway-default-endpoint-enabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [apigatewayDefaultEndpointEnabled]).map(
      (finding) => finding.ruleId
    );

  it('flags a RestApi with the default endpoint enabled when a custom domain is present', () => {
    expect(
      run({
        Resources: {
          Domain: {
            Type: 'AWS::ApiGateway::DomainName',
            Properties: { DomainName: 'api.example.com' },
          },
          Api: {
            Type: 'AWS::ApiGateway::RestApi',
            Properties: { Name: 'x' },
          },
        },
      })
    ).toContain('apigateway-default-endpoint-enabled');
  });

  it('does not flag a RestApi with DisableExecuteApiEndpoint true', () => {
    expect(
      run({
        Resources: {
          Domain: {
            Type: 'AWS::ApiGateway::DomainName',
            Properties: { DomainName: 'api.example.com' },
          },
          Api: {
            Type: 'AWS::ApiGateway::RestApi',
            Properties: { Name: 'x', DisableExecuteApiEndpoint: true },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag a RestApi when no custom domain is present', () => {
    expect(
      run({
        Resources: {
          Api: {
            Type: 'AWS::ApiGateway::RestApi',
            Properties: { Name: 'x' },
          },
        },
      })
    ).toHaveLength(0);
  });
});
