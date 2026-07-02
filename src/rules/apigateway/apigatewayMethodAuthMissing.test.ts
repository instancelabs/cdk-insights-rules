import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { apigatewayMethodAuthMissing } from './apigatewayMethodAuthMissing';

describe('api-gateway-method-auth-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [apigatewayMethodAuthMissing]);

  it('flags a REST method and an HTTP-API route with no authorization', () => {
    expect(
      run({
        Resources: {
          Method: {
            Type: 'AWS::ApiGateway::Method',
            Properties: { HttpMethod: 'GET', AuthorizationType: 'NONE' },
          },
          Route: {
            Type: 'AWS::ApiGatewayV2::Route',
            Properties: { RouteKey: 'GET /items' },
          },
        },
      })
    ).toHaveLength(2);
  });

  it('does not flag CORS preflight (OPTIONS) methods', () => {
    expect(
      run({
        Resources: {
          Preflight: {
            Type: 'AWS::ApiGateway::Method',
            Properties: { HttpMethod: 'OPTIONS', AuthorizationType: 'NONE' },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag authorized methods and routes', () => {
    expect(
      run({
        Resources: {
          Method: {
            Type: 'AWS::ApiGateway::Method',
            Properties: { HttpMethod: 'GET', AuthorizationType: 'AWS_IAM' },
          },
          Route: {
            Type: 'AWS::ApiGatewayV2::Route',
            Properties: { RouteKey: 'GET /items', AuthorizationType: 'JWT' },
          },
        },
      })
    ).toHaveLength(0);
  });
});
