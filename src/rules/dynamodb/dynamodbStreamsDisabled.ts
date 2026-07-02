import type { Rule } from '../../types';

/**
 * dynamodb-streams-disabled
 *
 * Advisory: streams are the hook for event-driven processing, auditing, and
 * replication. Tables that will never need change capture can suppress this.
 */
export const dynamodbStreamsDisabled: Rule = {
  metadata: {
    ruleId: 'dynamodb-streams-disabled',
    name: 'DynamoDB Streams Disabled',
    description:
      'Detects DynamoDB tables without streams enabled for change capture.',
    severity: 'LOW',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::DynamoDB::Table'],
    awsDocUrl:
      'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html',
    remediationSteps: [
      'Set StreamSpecification (e.g. NEW_AND_OLD_IMAGES) if change capture, auditing, or replication may be needed',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::DynamoDB::Table' &&
        !resource.Properties?.StreamSpecification
      ) {
        report(resourceId, {
          issue: 'DynamoDB table does not have streams enabled.',
          recommendation:
            'Consider StreamSpecification for item-level change capture — the hook for event-driven processing, audits, and replication.',
        });
      }
    }
  },

  example: {
    flagged: `import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

new dynamodb.CfnTable(this, 'Table', {
  keySchema: [{ attributeName: 'id', keyType: 'HASH' }],
  attributeDefinitions: [{ attributeName: 'id', attributeType: 'S' }],
  billingMode: 'PAY_PER_REQUEST',
});`,
    fixed: `import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

new dynamodb.CfnTable(this, 'Table', {
  keySchema: [{ attributeName: 'id', keyType: 'HASH' }],
  attributeDefinitions: [{ attributeName: 'id', attributeType: 'S' }],
  billingMode: 'PAY_PER_REQUEST',
  streamSpecification: { streamViewType: 'NEW_AND_OLD_IMAGES' },
});`,
  },
};
