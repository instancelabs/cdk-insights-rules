import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * rds-publicly-accessible
 *
 * `PubliclyAccessible: true` gives the DB instance a public IP; combined with
 * a permissive security group it is reachable from the internet. Databases
 * belong in private subnets behind a bastion, VPN, or SSM. Only a decidable
 * `true` is flagged — absent, false, or intrinsic values are not.
 */
export const rdsPubliclyAccessible: Rule = {
  metadata: {
    ruleId: 'rds-publicly-accessible',
    name: 'RDS Publicly Accessible',
    description:
      'Detects RDS instances with PubliclyAccessible set to true, exposing the database endpoint to the internet.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::RDS::DBInstance'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html',
    remediationSteps: [
      'Set PubliclyAccessible to false and place the instance in private subnets',
      'Access the database through a bastion host, VPN, or SSM Session Manager',
      'If public access is intentional (e.g. a restricted dev database), suppress this rule on the resource',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::RDS::DBInstance' &&
        asBoolean(resource.Properties?.PubliclyAccessible) === true
      ) {
        report(resourceId, {
          issue: 'RDS instance is publicly accessible from the internet.',
          recommendation:
            'Set PubliclyAccessible to false and access the database through private subnets, a bastion host, or VPN.',
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
  publiclyAccessible: true,
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'mysql',
  allocatedStorage: '20',
  storageEncrypted: true,
  publiclyAccessible: false,
});`,
  },
};
