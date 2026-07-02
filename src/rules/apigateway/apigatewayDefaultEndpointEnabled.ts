import type { Rule } from '../../types';

/**
 * Resolve an API reference (`{ Ref: 'Api' }` or a literal rest-api id) to a
 * logical id where possible. Literal ids refer to APIs outside the template.
 */
const resolveApiLogicalId = (value: unknown): string | undefined => {
  if (value && typeof value === 'object') {
    const ref = (value as Record<string, unknown>).Ref;
    if (typeof ref === 'string') {
      return ref;
    }
  }
  return undefined;
};

/**
 * apigateway-default-endpoint-enabled — default execute-api endpoint left on
 * while a custom domain is mapped to the API.
 *
 * When a REST API is fronted by a custom domain (and typically a WAF or other
 * edge controls), leaving the default `execute-api` endpoint enabled lets
 * clients call the API directly and bypass those controls. To keep false
 * positives low, this rule only fires for a REST API that a mapping
 * (`AWS::ApiGateway::BasePathMapping` or `AWS::ApiGatewayV2::ApiMapping`)
 * actually ties to a custom domain in the same template — a domain for some
 * *other* API never flags this one.
 */
export const apigatewayDefaultEndpointEnabled: Rule = {
  metadata: {
    ruleId: 'apigateway-default-endpoint-enabled',
    name: 'API Gateway Default Endpoint Enabled With Custom Domain',
    description:
      'Detects REST APIs that leave the default execute-api endpoint enabled while a custom domain is mapped to them, letting clients bypass the domain and its edge controls.',
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

    // Logical ids of REST APIs that a mapping ties to a custom domain.
    const mappedApiIds = new Set<string>();
    for (const [, resource] of resources) {
      if (resource.Type === 'AWS::ApiGateway::BasePathMapping') {
        const apiId = resolveApiLogicalId(resource.Properties?.RestApiId);
        if (apiId) {
          mappedApiIds.add(apiId);
        }
      }
      if (resource.Type === 'AWS::ApiGatewayV2::ApiMapping') {
        const apiId = resolveApiLogicalId(resource.Properties?.ApiId);
        if (apiId) {
          mappedApiIds.add(apiId);
        }
      }
    }

    if (mappedApiIds.size === 0) {
      return;
    }

    for (const [resourceId, resource] of resources) {
      if (
        resource.Type === 'AWS::ApiGateway::RestApi' &&
        mappedApiIds.has(resourceId) &&
        resource.Properties?.DisableExecuteApiEndpoint !== true
      ) {
        report(resourceId, {
          issue:
            'API Gateway REST API leaves the default execute-api endpoint enabled while a custom domain is mapped to it.',
          recommendation:
            'Set DisableExecuteApiEndpoint to true so clients must go through the custom domain (and any WAF or edge controls) instead of the default execute-api URL.',
        });
      }
    }
  },

  example: {
    flagged: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

const domain = new apigateway.CfnDomainName(this, 'Domain', {
  domainName: 'api.example.com',
  regionalCertificateArn:
    'arn:aws:acm:us-east-1:111122223333:certificate/abcd',
  endpointConfiguration: { types: ['REGIONAL'] },
});
const api = new apigateway.CfnRestApi(this, 'Api', {
  name: 'my-api',
});
new apigateway.CfnBasePathMapping(this, 'Mapping', {
  domainName: domain.ref,
  restApiId: api.ref,
});`,
    fixed: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

const domain = new apigateway.CfnDomainName(this, 'Domain', {
  domainName: 'api.example.com',
  regionalCertificateArn:
    'arn:aws:acm:us-east-1:111122223333:certificate/abcd',
  endpointConfiguration: { types: ['REGIONAL'] },
});
const api = new apigateway.CfnRestApi(this, 'Api', {
  name: 'my-api',
  disableExecuteApiEndpoint: true,
});
new apigateway.CfnBasePathMapping(this, 'Mapping', {
  domainName: domain.ref,
  restApiId: api.ref,
});`,
  },
};
