import type { Rule } from '../../types';

/**
 * glue-job-encryption-missing
 *
 * Without a SecurityConfiguration, a Glue job writes bookmarks, S3 output,
 * and CloudWatch logs unencrypted.
 */
export const glueJobEncryptionMissing: Rule = {
  metadata: {
    ruleId: 'glue-job-encryption-missing',
    name: 'Glue Job Encryption Missing',
    description:
      'Detects Glue jobs without a security configuration for encryption.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Glue::Job'],
    awsDocUrl:
      'https://docs.aws.amazon.com/glue/latest/dg/encryption-security-configuration.html',
    remediationSteps: [
      'Create a Glue SecurityConfiguration (S3/CloudWatch/bookmark encryption) and set it on the job',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::Glue::Job' &&
        !resource.Properties?.SecurityConfiguration
      ) {
        report(resourceId, {
          issue: 'Glue job does not have a security configuration specified.',
          recommendation:
            'Attach a SecurityConfiguration so job bookmarks, S3 data, and CloudWatch logs are encrypted.',
        });
      }
    }
  },

  example: {
    flagged: `import * as glue from 'aws-cdk-lib/aws-glue';

new glue.CfnJob(this, 'Job', {
  name: 'etl-job',
  role: 'arn:aws:iam::111122223333:role/glue-job-role',
  command: {
    name: 'glueetl',
    scriptLocation: 's3://my-scripts/etl.py',
  },
});`,
    fixed: `import * as glue from 'aws-cdk-lib/aws-glue';

new glue.CfnJob(this, 'Job', {
  name: 'etl-job',
  role: 'arn:aws:iam::111122223333:role/glue-job-role',
  command: {
    name: 'glueetl',
    scriptLocation: 's3://my-scripts/etl.py',
  },
  securityConfiguration: 'my-security-configuration',
});`,
  },
};
