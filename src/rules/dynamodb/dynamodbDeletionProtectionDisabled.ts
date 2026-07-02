import type { Rule } from '../../types';

/**
 * dynamodb-deletion-protection-disabled
 *
 * A DynamoDB table without deletion protection can be destroyed by an
 * accidental stack update, a console action, or a bad IaC change. Enabling
 * deletion protection blocks the delete until it is explicitly turned off.
 */
export const dynamodbDeletionProtectionDisabled: Rule = {
  metadata: {
    ruleId: 'dynamodb-deletion-protection-disabled',
    name: 'DynamoDB Deletion Protection Disabled',
    description:
      'Detects DynamoDB tables without deletion protection, which can be destroyed by an accidental stack update or delete.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::DynamoDB::Table'],
    awsDocUrl:
      'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html#WorkingWithTables.Basics.DeletionProtection',
    remediationSteps: [
      'Set DeletionProtectionEnabled to true on production tables',
      'Use CloudFormation DeletionPolicy: Retain as defence in depth',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::DynamoDB::Table' &&
        resource.Properties?.DeletionProtectionEnabled !== true
      ) {
        report(resourceId, {
          issue: 'DynamoDB table does not have deletion protection enabled.',
          recommendation:
            'Set DeletionProtectionEnabled to true to prevent accidental table deletion via stack updates or console actions.',
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
  deletionProtectionEnabled: true,
});`,
  },
};
