import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * dynamodb-deletion-protection-disabled
 *
 * A DynamoDB table without deletion protection can be destroyed by an
 * accidental stack update, a console action, or a bad IaC change. Enabling
 * deletion protection blocks the delete until it is explicitly turned off.
 * Covers both `AWS::DynamoDB::Table` and `AWS::DynamoDB::GlobalTable` (where
 * protection is set per replica).
 */
export const dynamodbDeletionProtectionDisabled: Rule = {
  metadata: {
    ruleId: 'dynamodb-deletion-protection-disabled',
    name: 'DynamoDB Deletion Protection Disabled',
    description:
      'Detects DynamoDB tables (and global-table replicas) without deletion protection, which can be destroyed by an accidental stack update or delete.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::DynamoDB::Table', 'AWS::DynamoDB::GlobalTable'],
    awsDocUrl:
      'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html#WorkingWithTables.Basics.DeletionProtection',
    remediationSteps: [
      'Set DeletionProtectionEnabled to true on production tables (per replica for global tables)',
      'Use CloudFormation DeletionPolicy: Retain as defence in depth',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    // Not protected only when decidably false/absent — intrinsics are unknown,
    // and CloudFormation accepts the string "true" as a boolean.
    const isUnprotected = (value: unknown): boolean =>
      !isIntrinsic(value) && asBoolean(value) !== true;

    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::DynamoDB::Table' &&
        isUnprotected(resource.Properties?.DeletionProtectionEnabled)
      ) {
        report(resourceId, {
          issue: 'DynamoDB table does not have deletion protection enabled.',
          recommendation:
            'Set DeletionProtectionEnabled to true to prevent accidental table deletion via stack updates or console actions.',
        });
      }

      if (resource.Type === 'AWS::DynamoDB::GlobalTable') {
        const replicas = resource.Properties?.Replicas;
        if (
          Array.isArray(replicas) &&
          replicas.some((replica) =>
            isUnprotected(replica?.DeletionProtectionEnabled)
          )
        ) {
          report(resourceId, {
            issue:
              'DynamoDB global table has a replica without deletion protection enabled.',
            recommendation:
              'Set DeletionProtectionEnabled to true on every replica to prevent accidental table deletion via stack updates or console actions.',
          });
        }
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
