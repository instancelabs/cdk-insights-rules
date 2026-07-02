import type { Rule } from '../../types';

/**
 * apigateway-default-endpoint-enabled — default execute-api endpoint left on
 * while a custom domain is configured.
 *
 * When a REST API is fronted by a custom domain (and typically a WAF or other
 * edge controls), leaving the default `execute-api` endpoint enabled lets
 * clients call the API directly and bypass those controls. This rule only
 * fires when a custom domain is present in the template.
 */
export const apigatewayDefaultEndpointEnabled: Rule = {
  metadata: {
    ruleId: 'apigateway-default-endpoint-enabled',
    name: 'API Gateway Default Endpoint Enabled With Custom Domain',
    description:
      'Detects REST APIs that leave the default execute-api endpoint enabled while a custom domain is configured, letting clients bypass the domain and its edge controls.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ApiGateway::RestApi'],
    awsDocUrl:
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-disable-default-endpoint.html',
    remediationSteps: [
      'Set DisableExecuteApiEndpoint to true on the REST API',
      'Route all traffic through the custom domain and its WAF / edge controls',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    const resources = Object.entries(template.Resources ?? {});

    const hasCustomDomain = resources.some(
      ([, resource]) =>
        resource.Type === 'AWS::ApiGateway::DomainName' ||
        resource.Type === 'AWS::ApiGatewayV2::DomainName'
    );

    if (!hasCustomDomain) {
      return;
    }

    for (const [resourceId, resource] of resources) {
      if (
        resource.Type === 'AWS::ApiGateway::RestApi' &&
        resource.Properties?.DisableExecuteApiEndpoint !== true
      ) {
        report(resourceId, {
          issue:
            'API Gateway REST API leaves the default execute-api endpoint enabled while a custom domain is configured.',
          recommendation:
            'Set DisableExecuteApiEndpoint to true so clients must go through the custom domain (and any WAF or edge controls) instead of the default execute-api URL.',
        });
      }
    }
  },

  example: {
    flagged: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnDomainName(this, 'Domain', {
  domainName: 'api.example.com',
  regionalCertificateArn:
    'arn:aws:acm:us-east-1:111122223333:certificate/abcd',
  endpointConfiguration: { types: ['REGIONAL'] },
});
new apigateway.CfnRestApi(this, 'Api', {
  name: 'my-api',
});`,
    fixed: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnDomainName(this, 'Domain', {
  domainName: 'api.example.com',
  regionalCertificateArn:
    'arn:aws:acm:us-east-1:111122223333:certificate/abcd',
  endpointConfiguration: { types: ['REGIONAL'] },
});
new apigateway.CfnRestApi(this, 'Api', {
  name: 'my-api',
  disableExecuteApiEndpoint: true,
});`,
  },
};
