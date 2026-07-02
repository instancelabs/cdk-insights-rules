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

  it('does not flag a Stage throttled by a usage plan (Ref)', () => {
    expect(
      run({
        Resources: {
          Stage: { Type: 'AWS::ApiGateway::Stage', Properties: {} },
          Plan: {
            Type: 'AWS::ApiGateway::UsagePlan',
            Properties: {
              Throttle: { RateLimit: 100, BurstLimit: 200 },
              ApiStages: [{ ApiId: { Ref: 'Api' }, Stage: { Ref: 'Stage' } }],
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag a Stage covered by a per-stage usage-plan throttle (literal stage name)', () => {
    expect(
      run({
        Resources: {
          Stage: {
            Type: 'AWS::ApiGateway::Stage',
            Properties: { StageName: 'prod' },
          },
          Plan: {
            Type: 'AWS::ApiGateway::UsagePlan',
            Properties: {
              ApiStages: [
                {
                  ApiId: 'abc123',
                  Stage: 'prod',
                  Throttle: { '/*/*': { RateLimit: 50, BurstLimit: 100 } },
                },
              ],
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('flags a Stage referenced by a usage plan that sets no throttle', () => {
    expect(
      run({
        Resources: {
          Stage: { Type: 'AWS::ApiGateway::Stage', Properties: {} },
          Plan: {
            Type: 'AWS::ApiGateway::UsagePlan',
            Properties: {
              ApiStages: [{ ApiId: { Ref: 'Api' }, Stage: { Ref: 'Stage' } }],
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
