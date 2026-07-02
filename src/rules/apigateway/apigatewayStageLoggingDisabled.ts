import type { Rule } from '../../types';

/**
 * api-gateway-logging-disabled
 *
 * A stage with neither access logging nor execution logging leaves no record
 * of who called the API or why requests failed. (The product catalog's
 * metadata for this ruleId mapped to a different check; this is a faithful
 * implementation of what the name promises.)
 */
export const apigatewayStageLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'api-gateway-logging-disabled',
    name: 'API Gateway Stage Logging Disabled',
    description:
      'Detects API Gateway stages with neither access logging nor execution logging configured.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    awsDocUrl:
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html',
    remediationSteps: [
      'Set AccessLogSetting with a destination log group and format',
      'Or enable execution logging via MethodSettings LoggingLevel (INFO/ERROR)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ApiGateway::Stage') {
        continue;
      }
      const props = resource.Properties ?? {};
      const hasAccessLogs = Boolean(props.AccessLogSetting?.DestinationArn);
      const methodSettings = props.MethodSettings;
      const hasExecutionLogs =
        Array.isArray(methodSettings) &&
        methodSettings.some(
          (setting) =>
            setting?.LoggingLevel === 'INFO' ||
            setting?.LoggingLevel === 'ERROR'
        );
      if (!hasAccessLogs && !hasExecutionLogs) {
        report(resourceId, {
          issue:
            'API Gateway stage has neither access logging nor execution logging configured.',
          recommendation:
            'Configure AccessLogSetting (who called what) and/or MethodSettings LoggingLevel (why requests failed) so API traffic is auditable.',
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
  methodSettings: [
    {
      httpMethod: '*',
      resourcePath: '/*',
      throttlingRateLimit: 100,
      throttlingBurstLimit: 200,
    },
  ],
});`,
    fixed: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnStage(this, 'Stage', {
  restApiId: 'abc123',
  deploymentId: 'dep123',
  stageName: 'prod',
  accessLogSetting: {
    destinationArn:
      'arn:aws:logs:eu-west-2:111122223333:log-group:/apigw/access',
    format: '$context.requestId $context.status',
  },
  methodSettings: [
    {
      httpMethod: '*',
      resourcePath: '/*',
      loggingLevel: 'INFO',
      throttlingRateLimit: 100,
      throttlingBurstLimit: 200,
    },
  ],
});`,
  },
};
