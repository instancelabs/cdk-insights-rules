import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * redshift-encryption-disabled
 *
 * Redshift clusters are not encrypted by default. An unencrypted warehouse
 * means unencrypted data blocks and snapshots. Values set via intrinsics are
 * undecidable and never flagged.
 */
export const redshiftEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'redshift-encryption-disabled',
    name: 'Redshift Encryption Disabled',
    description:
      'Detects Redshift clusters without encryption at rest enabled.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Redshift::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html',
    remediationSteps: [
      'Set Encrypted to true (optionally with a KmsKeyId customer-managed key)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Redshift::Cluster') {
        continue;
      }
      const encrypted = resource.Properties?.Encrypted;
      if (isIntrinsic(encrypted) || asBoolean(encrypted) === true) {
        continue;
      }
      report(resourceId, {
        issue: 'Redshift cluster does not have encryption at rest enabled.',
        recommendation:
          'Set Encrypted to true and optionally specify a KmsKeyId to protect warehouse data and snapshots at rest.',
      });
    }
  },

  example: {
    flagged: `import * as redshift from 'aws-cdk-lib/aws-redshift';

new redshift.CfnCluster(this, 'Cluster', {
  clusterType: 'single-node',
  dbName: 'analytics',
  masterUsername: 'admin',
  masterUserPassword: 'example-Password1',
  nodeType: 'dc2.large',
});`,
    fixed: `import * as redshift from 'aws-cdk-lib/aws-redshift';

new redshift.CfnCluster(this, 'Cluster', {
  clusterType: 'single-node',
  dbName: 'analytics',
  masterUsername: 'admin',
  masterUserPassword: 'example-Password1',
  nodeType: 'dc2.large',
  encrypted: true,
});`,
  },
};
