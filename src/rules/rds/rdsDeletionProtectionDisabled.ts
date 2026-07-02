import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { CfnResource, Rule } from '../../types';

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
 * rds-deletion-protection-disabled
 *
 * Without deletion protection, a bad stack update or console action can
 * destroy the database. Aurora member instances inherit protection from the
 * cluster and are exempt.
 */
export const rdsDeletionProtectionDisabled: Rule = {
  metadata: {
    ruleId: 'rds-deletion-protection-disabled',
    name: 'RDS Deletion Protection Disabled',
    description:
      'Detects RDS instances and clusters without deletion protection.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html',
    remediationSteps: [
      'Set DeletionProtection to true on production databases',
      'Use DeletionPolicy: Retain / Snapshot as defence in depth',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'NIST'],
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
      const protection = resource.Properties?.DeletionProtection;
      if (isIntrinsic(protection) || asBoolean(protection) === true) {
        continue;
      }
      report(resourceId, {
        issue: `RDS ${isCluster ? 'cluster' : 'instance'} does not have deletion protection enabled.`,
        recommendation:
          'Set DeletionProtection to true so the database cannot be deleted by an accidental stack update or console action.',
      });
    }
  },

  example: {
    flagged: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
  deletionProtection: true,
});`,
  },
};
