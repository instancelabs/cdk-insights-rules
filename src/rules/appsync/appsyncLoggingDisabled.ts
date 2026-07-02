import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * appsync-logging-disabled
 *
 * Without LogConfig (and X-Ray) a GraphQL API offers no visibility into
 * resolver failures or latency.
 */
export const appsyncLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'appsync-logging-disabled',
    name: 'AppSync Logging Disabled',
    description:
      'Detects AppSync APIs without logging or X-Ray tracing configured.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::AppSync::GraphQLApi'],
    awsDocUrl:
      'https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html',
    remediationSteps: [
      'Configure LogConfig with FieldLogLevel ERROR or ALL',
      'Enable XrayEnabled for distributed tracing',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::AppSync::GraphQLApi') {
        continue;
      }
      const props = resource.Properties ?? {};
      const logConfig = props.LogConfig;
      if (!logConfig) {
        report(resourceId, {
          issue: 'AppSync API does not have logging configured.',
          recommendation:
            'Enable LogConfig so request and resolver logs land in CloudWatch for debugging and monitoring.',
        });
      } else if (logConfig.FieldLogLevel === 'NONE') {
        report(resourceId, {
          issue: 'AppSync API has field-level logging disabled.',
          recommendation:
            'Set FieldLogLevel to ERROR or ALL to capture resolver execution details.',
        });
      }
      const xray = props.XrayEnabled;
      if (!isIntrinsic(xray) && asBoolean(xray) !== true) {
        report(resourceId, {
          issue: 'AppSync API does not have X-Ray tracing enabled.',
          recommendation:
            'Enable XrayEnabled for distributed tracing across resolvers and data sources.',
        });
      }
    }
  },

  example: {
    flagged: `import * as appsync from 'aws-cdk-lib/aws-appsync';

new appsync.CfnGraphQLApi(this, 'Api', {
  name: 'my-api',
  authenticationType: 'AWS_IAM',
});`,
    fixed: `import * as appsync from 'aws-cdk-lib/aws-appsync';

new appsync.CfnGraphQLApi(this, 'Api', {
  name: 'my-api',
  authenticationType: 'AWS_IAM',
  xrayEnabled: true,
  logConfig: {
    cloudWatchLogsRoleArn:
      'arn:aws:iam::111122223333:role/appsync-logs-role',
    fieldLogLevel: 'ERROR',
  },
});`,
  },
};
