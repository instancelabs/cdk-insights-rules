import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { apigatewayThrottlingMissing } from './apigatewayThrottlingMissing';

describe('apigateway-throttling-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [apigatewayThrottlingMissing]).map(
      (finding) => finding.ruleId
    );

  it('flags a Stage with no MethodSettings', () => {
    expect(
      run({
        Resources: {
          Stage: { Type: 'AWS::ApiGateway::Stage', Properties: {} },
        },
      })
    ).toContain('apigateway-throttling-missing');
  });

  it('flags a Stage whose MethodSettings set neither throttling field', () => {
    expect(
      run({
        Resources: {
          Stage: {
            Type: 'AWS::ApiGateway::Stage',
            Properties: {
              MethodSettings: [
                { HttpMethod: '*', ResourcePath: '/*', LoggingLevel: 'INFO' },
              ],
            },
          },
        },
      })
    ).toContain('apigateway-throttling-missing');
  });

  it('does not flag a Stage that sets both ThrottlingRateLimit and ThrottlingBurstLimit', () => {
    expect(
      run({
        Resources: {
          Stage: {
            Type: 'AWS::ApiGateway::Stage',
            Properties: {
              MethodSettings: [
                {
                  HttpMethod: '*',
                  ResourcePath: '/*',
                  ThrottlingRateLimit: 100,
                  ThrottlingBurstLimit: 200,
                },
              ],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
