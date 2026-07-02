import type { Rule } from '../../types';

/**
 * dynamodb-pitr-disabled
 *
 * Point-in-time recovery is the 35-day continuous-backup safety net for
 * fat-finger deletes and bad writes. Global tables carry the setting per
 * replica.
 */
export const dynamodbPitrDisabled: Rule = {
  metadata: {
    ruleId: 'dynamodb-pitr-disabled',
    name: 'DynamoDB PITR Disabled',
    description:
      'Detects DynamoDB tables (and global-table replicas) without point-in-time recovery.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::DynamoDB::Table', 'AWS::DynamoDB::GlobalTable'],
    awsDocUrl:
      'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html',
    remediationSteps: [
      'Set PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled to true (per replica for global tables)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      const isTable = resource.Type === 'AWS::DynamoDB::Table';
      const isGlobalTable = resource.Type === 'AWS::DynamoDB::GlobalTable';
      if (!isTable && !isGlobalTable) {
        continue;
      }
      let covered: boolean;
      if (isTable) {
        covered =
          resource.Properties?.PointInTimeRecoverySpecification
            ?.PointInTimeRecoveryEnabled === true;
      } else {
        const replicas = resource.Properties?.Replicas;
        covered =
          Array.isArray(replicas) &&
          replicas.length > 0 &&
          replicas.every(
            (replica) =>
              replica?.PointInTimeRecoverySpecification
                ?.PointInTimeRecoveryEnabled === true
          );
      }
      if (!covered) {
        report(resourceId, {
          issue: `DynamoDB ${isGlobalTable ? 'global table' : 'table'} does not have point-in-time recovery enabled.`,
          recommendation:
            'Enable PointInTimeRecoverySpecification for continuous backups over the last 35 days — the recovery path for accidental writes and deletes.',
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
  pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
});`,
  },
};
