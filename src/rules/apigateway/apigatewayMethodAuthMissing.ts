import type { Rule } from '../../types';

/**
 * apigateway-method-auth-missing
 *
 * A REST Method or HTTP-API Route with AuthorizationType NONE is a public,
 * unauthenticated entry point to the backend. CORS preflight (OPTIONS)
 * methods are exempt — browsers require them to be unauthenticated.
 */
export const apigatewayMethodAuthMissing: Rule = {
  metadata: {
    ruleId: 'apigateway-method-auth-missing',
    legacyRuleIds: ['api-gateway-method-auth-missing'],
    name: 'API Gateway Method Without Authorization',
    description:
      'Detects API Gateway methods and routes with no authorization (AuthorizationType NONE), excluding CORS preflight.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ApiGateway::Method', 'AWS::ApiGatewayV2::Route'],
    awsDocUrl:
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html',
    remediationSteps: [
      'Set AuthorizationType to AWS_IAM, COGNITO_USER_POOLS, or CUSTOM (REST), or JWT (HTTP API)',
      'If the endpoint is intentionally public (e.g. a webhook receiver), add an API key plus WAF rate limiting and suppress this rule on the resource',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      const isMethod = resource.Type === 'AWS::ApiGateway::Method';
      const isRoute = resource.Type === 'AWS::ApiGatewayV2::Route';
      if (!isMethod && !isRoute) {
        continue;
      }
      const props = resource.Properties ?? {};
      // CORS preflight must be unauthenticated for browsers to work.
      if (
        isMethod &&
        typeof props.HttpMethod === 'string' &&
        props.HttpMethod.toUpperCase() === 'OPTIONS'
      ) {
        continue;
      }
      const authType = props.AuthorizationType;
      if (authType === undefined || authType === 'NONE') {
        report(resourceId, {
          issue: `API Gateway ${isMethod ? 'method' : 'route'} has no authorization (AuthorizationType is NONE).`,
          recommendation:
            'Set AuthorizationType to AWS_IAM, COGNITO_USER_POOLS, CUSTOM, or JWT so the endpoint is not publicly invocable without credentials.',
        });
      }
    }
  },

  example: {
    flagged: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnMethod(this, 'Method', {
  restApiId: 'abc123',
  resourceId: 'res123',
  httpMethod: 'GET',
  authorizationType: 'NONE',
});`,
    fixed: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnMethod(this, 'Method', {
  restApiId: 'abc123',
  resourceId: 'res123',
  httpMethod: 'GET',
  authorizationType: 'AWS_IAM',
});`,
  },
};
