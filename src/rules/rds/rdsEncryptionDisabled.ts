import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { CfnResource, Rule } from '../../types';

/**
 * An Aurora *member* instance inherits encryption from its cluster, so
 * flagging it would duplicate (or contradict) the cluster-level finding.
 */
const isAuroraMemberInstance = (resource: CfnResource): boolean => {
  const props = resource.Properties ?? {};
  if (props.DBClusterIdentifier !== undefined) {
    return true;
  }
  const engine = props.Engine;
  return (
    typeof engine === 'string' && engine.toLowerCase().startsWith('aurora')
  );
};

/**
 * rds-encryption-disabled
 *
 * Storage encryption cannot be enabled on an existing RDS instance or cluster
 * — it requires a snapshot-and-restore — so catching it at synth time is the
 * cheap moment. Flags DB instances and clusters where StorageEncrypted is not
 * decidably true; Aurora member instances are exempt (the cluster carries the
 * setting).
 */
export const rdsEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'rds-encryption-disabled',
    name: 'RDS Encryption Disabled',
    description:
      'Detects RDS instances and clusters without storage encryption at rest.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    remediationSteps: [
      'Set StorageEncrypted to true (in CDK: storageEncrypted: true, optionally with storageEncryptionKey)',
      'For existing unencrypted databases, create an encrypted snapshot and restore from it',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      const isCluster = resource.Type === 'AWS::RDS::DBCluster';
      const isInstance = resource.Type === 'AWS::RDS::DBInstance';
      if (!isCluster && !isInstance) {
        continue;
      }
      if (isInstance && isAuroraMemberInstance(resource)) {
        continue;
      }
      const encrypted = resource.Properties?.StorageEncrypted;
      if (isIntrinsic(encrypted) || asBoolean(encrypted) === true) {
        continue;
      }
      report(resourceId, {
        issue: `RDS ${isCluster ? 'cluster' : 'instance'} does not have storage encryption enabled.`,
        recommendation:
          'Set StorageEncrypted to true — encryption cannot be enabled later without a snapshot-and-restore migration.',
      });
    }
  },

  example: {
    flagged: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
});`,
  },
};
