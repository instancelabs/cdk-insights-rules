import type { Rule } from '../../types';

/**
 * rds-master-password-plaintext
 *
 * A literal MasterUserPassword sits in plaintext in the synthesized template,
 * in CloudFormation's stored template, and in every artifact bucket and log
 * that touches them. Dynamic references ('{{resolve:secretsmanager:...}}',
 * '{{resolve:ssm-secure:...}}') and intrinsics (Ref to a NoEcho parameter,
 * Fn::* expressions) resolve at deploy time and are fine — only a decidable
 * literal is flagged. The companion to ecs-secrets-plaintext.
 */

const isDynamicReference = (value: string): boolean =>
  value.startsWith('{{resolve:');

export const rdsMasterPasswordPlaintext: Rule = {
  metadata: {
    ruleId: 'rds-master-password-plaintext',
    name: 'RDS Master Password In Plaintext',
    description:
      'Detects RDS instances and clusters whose MasterUserPassword is a literal string in the template rather than a Secrets Manager/SSM dynamic reference or managed credential.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html',
    remediationSteps: [
      'Use ManageMasterUserPassword (in CDK: rds.Credentials.fromGeneratedSecret or manageMasterUserPassword: true) so RDS creates and rotates the credential in Secrets Manager',
      "Or reference an existing secret with a dynamic reference: '{{resolve:secretsmanager:my-secret:SecretString:password}}'",
      'Rotate any credential that has already been committed in plaintext',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
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
      const password = resource.Properties?.MasterUserPassword;
      // Intrinsics are objects and fail the string check; dynamic references
      // ('{{resolve:...}}') resolve at deploy time. Only literals remain.
      if (typeof password !== 'string' || isDynamicReference(password)) {
        continue;
      }
      report(resourceId, {
        issue:
          'RDS master password is a plaintext literal in the template — it is visible to anyone who can read the template, the stack, or the deploy artifacts.',
        recommendation:
          'Let RDS manage the credential (ManageMasterUserPassword / rds.Credentials.fromGeneratedSecret) or use a Secrets Manager dynamic reference, then rotate the exposed password.',
      });
    }
  },

  example: {
    flagged: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'postgres',
  allocatedStorage: '20',
  masterUsername: 'admin',
  masterUserPassword: 'SuperSecretPassw0rd!',
});`,
    fixed: `import * as rds from 'aws-cdk-lib/aws-rds';

new rds.CfnDBInstance(this, 'Db', {
  dbInstanceClass: 'db.t3.micro',
  engine: 'postgres',
  allocatedStorage: '20',
  masterUsername: 'admin',
  manageMasterUserPassword: true,
});`,
  },
};
