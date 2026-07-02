import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * rds-multi-az-gp2-storage
 *
 * Multi-AZ doubles storage, so gp2 (or the unset default, which is gp2)
 * doubles the overpayment — gp3 delivers the same baseline for less.
 * (Ported from the product's rds-multi-az-disabled, whose implementation
 * actually checks storage type on Multi-AZ instances; the open catalog names
 * the rule for what it detects.)
 */
export const rdsMultiAzGp2Storage: Rule = {
  metadata: {
    ruleId: 'rds-multi-az-gp2-storage',
    name: 'RDS Multi-AZ On gp2 Storage',
    description:
      'Detects Multi-AZ RDS instances using gp2 (or default) storage where gp3 would cost less.',
    severity: 'MEDIUM',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::RDS::DBInstance'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_Storage.html',
    remediationSteps: [
      'Set StorageType to gp3 — Multi-AZ doubles storage, doubling the gp2 premium',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::RDS::DBInstance') {
        continue;
      }
      const props = resource.Properties ?? {};
      if (asBoolean(props.MultiAZ) !== true) {
        continue;
      }
      const storageType = props.StorageType;
      if (storageType === 'gp2' || storageType === undefined) {
        report(resourceId, {
          issue:
            storageType === 'gp2'
              ? 'Multi-AZ RDS instance uses gp2 storage — the standby doubles the gp2 premium.'
              : 'Multi-AZ RDS instance does not set a storage type (defaults to gp2).',
          recommendation:
            'Set StorageType to gp3 for the same baseline performance at lower cost, doubled across the Multi-AZ standby.',
        });
      }
    }
  },

  example: {
    flagged: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '100',
  storageEncrypted: true,
  multiAz: true,
  storageType: 'gp2',
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '100',
  storageEncrypted: true,
  multiAz: true,
  storageType: 'gp3',
});`,
  },
};
