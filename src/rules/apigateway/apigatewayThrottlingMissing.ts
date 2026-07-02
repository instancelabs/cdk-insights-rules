import type { Rule } from '../../types';

/**
 * apigateway-throttling-missing — API Gateway stage with no method-level
 * throttling.
 *
 * A stage that sets no rate or burst limits leaves its backend integrations
 * exposed to traffic spikes and uncontrolled cost. This rule reports any stage
 * whose MethodSettings define neither a ThrottlingRateLimit nor a
 * ThrottlingBurstLimit on any entry.
 */
export const apigatewayThrottlingMissing: Rule = {
  metadata: {
    ruleId: 'apigateway-throttling-missing',
    name: 'API Gateway Stage Missing Throttling',
    description:
      'Detects API Gateway stages that configure no method-level rate or burst limits, leaving backends exposed to traffic spikes and uncontrolled cost.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    awsDocUrl:
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html',
    remediationSteps: [
      'Add MethodSettings with ThrottlingRateLimit and ThrottlingBurstLimit (e.g. for HttpMethod "*")',
      'Tune per-method limits for hot paths',
    ],
    complianceFrameworks: ['SOC2'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ApiGateway::Stage') {
        continue;
      }

      const methodSettings = resource.Properties?.MethodSettings;
      const hasThrottling =
        Array.isArray(methodSettings) &&
        methodSettings.some(
          (setting) =>
            setting?.ThrottlingBurstLimit !== undefined ||
            setting?.ThrottlingRateLimit !== undefined
        );

      if (!hasThrottling) {
        report(resourceId, {
          issue:
            'API Gateway stage does not configure request throttling (no method-level rate or burst limits).',
          recommendation:
            'Add MethodSettings with ThrottlingRateLimit and ThrottlingBurstLimit (e.g. for HttpMethod "*") to protect backend integrations from traffic spikes and control cost.',
        });
      }
    }
  },

  example: {
    flagged: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnStage(this, 'Stage', {
  restApiId: 'abc123',
  deploymentId: 'dep123',
  stageName: 'prod',
});`,
    fixed: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnStage(this, 'Stage', {
  restApiId: 'abc123',
  deploymentId: 'dep123',
  stageName: 'prod',
  methodSettings: [
    {
      httpMethod: '*',
      resourcePath: '/*',
      throttlingRateLimit: 100,
      throttlingBurstLimit: 200,
    },
  ],
});`,
  },
};
