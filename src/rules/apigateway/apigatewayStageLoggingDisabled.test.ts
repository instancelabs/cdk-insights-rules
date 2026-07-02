import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { apigatewayStageLoggingDisabled } from './apigatewayStageLoggingDisabled';

describe('api-gateway-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [apigatewayStageLoggingDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::ApiGateway::Stage', Properties: { ...properties } },
    },
  });

  it('flags a stage with no access or execution logging', () => {
    expect(run(res({}))).toHaveLength(1);
    expect(
      run(res({ MethodSettings: [{ LoggingLevel: 'OFF' }] }))
    ).toHaveLength(1);
  });

  it('does not flag access logs or execution logging', () => {
    expect(
      run(res({ AccessLogSetting: { DestinationArn: 'arn:lg' } }))
    ).toHaveLength(0);
    expect(
      run(res({ MethodSettings: [{ LoggingLevel: 'INFO' }] }))
    ).toHaveLength(0);
  });
});
