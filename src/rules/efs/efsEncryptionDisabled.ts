import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * efs-encryption-disabled
 *
 * EFS encryption can only be chosen at filesystem creation — an existing
 * unencrypted filesystem requires a data migration to fix. Values set via
 * intrinsics are undecidable and never flagged.
 */
export const efsEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'efs-encryption-disabled',
    name: 'EFS Encryption Disabled',
    description: 'Detects EFS file systems without encryption at rest.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EFS::FileSystem'],
    awsDocUrl:
      'https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html',
    remediationSteps: [
      'Set Encrypted to true (optionally with a KmsKeyId customer-managed key)',
      'Existing unencrypted file systems require migrating data to a new encrypted file system',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EFS::FileSystem') {
        continue;
      }
      const encrypted = resource.Properties?.Encrypted;
      if (isIntrinsic(encrypted) || asBoolean(encrypted) === true) {
        continue;
      }
      report(resourceId, {
        issue: 'EFS file system is not encrypted at rest.',
        recommendation:
          'Set Encrypted to true — encryption can only be enabled at creation, and fixing it later means migrating the data.',
      });
    }
  },

  example: {
    flagged: `import * as efs from 'aws-cdk-lib/aws-efs';

new efs.CfnFileSystem(this, 'FileSystem', {});`,
    fixed: `import * as efs from 'aws-cdk-lib/aws-efs';

new efs.CfnFileSystem(this, 'FileSystem', {
  encrypted: true,
});`,
  },
};
