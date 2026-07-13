import type { Rule } from '../../types';

/**
 * dynamodb-encryption-aws-owned-key
 *
 * Without an SSESpecification, DynamoDB encrypts with an AWS-owned key —
 * fine for general use, but compliance regimes (HIPAA, PCI-DSS) expect
 * customer-controlled keys with auditable rotation. Intrinsic/unknown
 * SSEEnabled values are never flagged.
 */
export const dynamodbEncryptionAwsOwnedKey: Rule = {
  metadata: {
    ruleId: 'dynamodb-encryption-aws-owned-key',
    name: 'DynamoDB Encryption Uses AWS-Owned Key',
    description:
      'Detects DynamoDB tables using the default AWS-owned key: no SSESpecification with SSEEnabled, which opts into at least the AWS-managed KMS key.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::DynamoDB::Table', 'AWS::DynamoDB::GlobalTable'],
    awsDocUrl:
      'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.howitworks.html',
    remediationSteps: [
      'Set SSESpecification.SSEEnabled to true (AWS-managed key) or add a customer-managed KMSMasterKeyId for compliance workloads',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
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
      const sseEnabled = resource.Properties?.SSESpecification?.SSEEnabled;
      if (sseEnabled === true) {
        continue;
      }
      // Intrinsics and other non-boolean values are undecidable — skip.
      if (sseEnabled !== undefined && typeof sseEnabled !== 'boolean') {
        continue;
      }
      report(resourceId, {
        issue: `DynamoDB ${isGlobalTable ? 'global table' : 'table'} is not configured with KMS encryption (defaults to an AWS-owned key).`,
        recommendation:
          'Set SSESpecification.SSEEnabled to true — add a customer-managed KMSMasterKeyId if your compliance regime requires customer-controlled rotation and audit.',
      });
    }
  },

  example: {
    flagged: `import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

new dynamodb.CfnTable(this, 'Table', {
  keySchema: [{ attributeName: 'id', keyType: 'HASH' }],
  attributeDefinitions: [{ attributeName: 'id', attributeType: 'S' }],
  billingMode: 'PAY_PER_REQUEST',
  deletionProtectionEnabled: true,
});`,
    fixed: `import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

new dynamodb.CfnTable(this, 'Table', {
  keySchema: [{ attributeName: 'id', keyType: 'HASH' }],
  attributeDefinitions: [{ attributeName: 'id', attributeType: 'S' }],
  billingMode: 'PAY_PER_REQUEST',
  deletionProtectionEnabled: true,
  sseSpecification: { sseEnabled: true },
});`,
  },
};
