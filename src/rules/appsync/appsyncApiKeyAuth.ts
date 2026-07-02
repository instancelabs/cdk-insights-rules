import type { Rule } from '../../types';

/**
 * appsync-api-key-auth
 *
 * API-key auth on AppSync is a shared static credential — fine for demos,
 * wrong for production. Only the primary AuthenticationType is checked;
 * an API key as an *additional* auth mode alongside IAM/Cognito is a common
 * legitimate pattern and is not flagged.
 */
export const appsyncApiKeyAuth: Rule = {
  metadata: {
    ruleId: 'appsync-api-key-auth',
    name: 'AppSync API Key Authentication',
    description:
      'Detects AppSync GraphQL APIs whose primary authentication is a static API key.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::AppSync::GraphQLApi'],
    awsDocUrl:
      'https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html',
    remediationSteps: [
      'Use AWS_IAM, AMAZON_COGNITO_USER_POOLS, or OPENID_CONNECT as the primary authentication for production workloads',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::AppSync::GraphQLApi' &&
        resource.Properties?.AuthenticationType === 'API_KEY'
      ) {
        report(resourceId, {
          issue:
            'AppSync API uses a static API key as its primary authentication.',
          recommendation:
            'Use AWS_IAM, AMAZON_COGNITO_USER_POOLS, or OPENID_CONNECT for production; API keys are shared static credentials suited to development or public read-only access.',
        });
      }
    }
  },

  example: {
    flagged: `import * as appsync from 'aws-cdk-lib/aws-appsync';

new appsync.CfnGraphQLApi(this, 'Api', {
  name: 'my-api',
  authenticationType: 'API_KEY',
});`,
    fixed: `import * as appsync from 'aws-cdk-lib/aws-appsync';

new appsync.CfnGraphQLApi(this, 'Api', {
  name: 'my-api',
  authenticationType: 'AMAZON_COGNITO_USER_POOLS',
  userPoolConfig: {
    userPoolId: 'eu-west-2_example',
    awsRegion: 'eu-west-2',
    defaultAction: 'ALLOW',
  },
});`,
  },
};
