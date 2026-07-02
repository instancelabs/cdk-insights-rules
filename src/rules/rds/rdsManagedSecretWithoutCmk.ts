import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * rds-managed-secret-without-cmk
 *
 * RDS-managed master-user secrets default to the AWS-managed
 * aws/secretsmanager key; a customer-managed key allows key-policy scoping,
 * cross-account sharing, and rotation audit.
 */
export const rdsManagedSecretWithoutCmk: Rule = {
  metadata: {
    ruleId: 'rds-managed-secret-without-cmk',
    name: 'RDS Managed Secret Without CMK',
    description:
      'Detects RDS-managed master-user secrets encrypted with the default AWS-managed key instead of a customer-managed KMS key.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html',
    remediationSteps: [
      'Set MasterUserSecret.KmsKeyId to a customer-managed KMS key',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type !== 'AWS::RDS::DBInstance' &&
        resource.Type !== 'AWS::RDS::DBCluster'
      ) {
        continue;
      }
      const props = resource.Properties ?? {};
      const usesManagedSecret =
        asBoolean(props.ManageMasterUserPassword) === true ||
        props.MasterUserSecret !== undefined;
      if (!usesManagedSecret) {
        continue;
      }
      if (props.MasterUserSecret?.KmsKeyId == null) {
        report(resourceId, {
          issue:
            'RDS managed master-user secret is encrypted with the AWS-managed aws/secretsmanager key rather than a customer-managed KMS key.',
          recommendation:
            'Set MasterUserSecret.KmsKeyId to a customer-managed key so the credential secret can be scoped, shared, and audited via its key policy.',
        });
      }
    }
  },

  example: {
    flagged: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
  manageMasterUserPassword: true,
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
  manageMasterUserPassword: true,
  masterUserSecret: {
    kmsKeyId:
      'arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  },
});`,
  },
};
