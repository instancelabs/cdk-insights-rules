import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { apigatewayDefaultEndpointEnabled } from './apigatewayDefaultEndpointEnabled';

describe('apigateway-default-endpoint-enabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [apigatewayDefaultEndpointEnabled]).map(
      (finding) => finding.resourceId
    );

  const domain = {
    Type: 'AWS::ApiGateway::DomainName',
    Properties: { DomainName: 'api.example.com' },
  };

  it('flags a RestApi with the default endpoint enabled when a mapping ties it to a custom domain', () => {
    expect(
      run({
        Resources: {
          Domain: domain,
          Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'x' } },
          Mapping: {
            Type: 'AWS::ApiGateway::BasePathMapping',
            Properties: {
              DomainName: 'api.example.com',
              RestApiId: { Ref: 'Api' },
            },
          },
        },
      })
    ).toContain('Api');
  });

  it('flags a RestApi mapped via an ApiGatewayV2 ApiMapping', () => {
    expect(
      run({
        Resources: {
          Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'x' } },
          Mapping: {
            Type: 'AWS::ApiGatewayV2::ApiMapping',
            Properties: {
              DomainName: 'api.example.com',
              ApiId: { Ref: 'Api' },
            },
          },
        },
      })
    ).toContain('Api');
  });

  it('does not flag a RestApi with DisableExecuteApiEndpoint true', () => {
    expect(
      run({
        Resources: {
          Domain: domain,
          Api: {
            Type: 'AWS::ApiGateway::RestApi',
            Properties: { Name: 'x', DisableExecuteApiEndpoint: true },
          },
          Mapping: {
            Type: 'AWS::ApiGateway::BasePathMapping',
            Properties: {
              DomainName: 'api.example.com',
              RestApiId: { Ref: 'Api' },
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag a RestApi when no custom domain is present', () => {
    expect(
      run({
        Resources: {
          Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'x' } },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag a RestApi when the domain is mapped to a different API', () => {
    expect(
      run({
        Resources: {
          Domain: domain,
          Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'x' } },
          OtherApi: {
            Type: 'AWS::ApiGateway::RestApi',
            Properties: { Name: 'y' },
          },
          Mapping: {
            Type: 'AWS::ApiGateway::BasePathMapping',
            Properties: {
              DomainName: 'api.example.com',
              RestApiId: { Ref: 'OtherApi' },
            },
          },
        },
      })
    ).toEqual(['OtherApi']);
  });

  it('does not flag a RestApi when a domain exists but nothing is mapped', () => {
    expect(
      run({
        Resources: {
          Domain: domain,
          Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'x' } },
        },
      })
    ).toHaveLength(0);
  });
});
