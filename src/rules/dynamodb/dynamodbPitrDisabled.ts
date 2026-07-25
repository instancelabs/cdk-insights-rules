import { asBoolean, isIntrinsic } from '../../cfn.js';
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
      // Uncovered only when decidably false/absent — intrinsics are unknown,
      // and CloudFormation accepts the string "true" as a boolean.
      const isUncovered = (spec: unknown): boolean => {
        if (isIntrinsic(spec)) {
          return false;
        }
        const enabled = (spec as Record<string, unknown> | undefined)
          ?.PointInTimeRecoveryEnabled;
        return !isIntrinsic(enabled) && asBoolean(enabled) !== true;
      };

      let uncovered: boolean;
      if (isTable) {
        uncovered = isUncovered(
          resource.Properties?.PointInTimeRecoverySpecification
        );
      } else {
        const replicas = resource.Properties?.Replicas;
        if (isIntrinsic(replicas)) {
          continue; // whole replica list is undecidable
        }
        // A missing/empty Replicas list is decidably uncovered; an intrinsic
        // replica entry (conditional region) is unknown and skipped.
        uncovered = !Array.isArray(replicas)
          ? true
          : replicas.some(
              (replica) =>
                !isIntrinsic(replica) &&
                isUncovered(replica?.PointInTimeRecoverySpecification)
            );
      }
      if (uncovered) {
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
