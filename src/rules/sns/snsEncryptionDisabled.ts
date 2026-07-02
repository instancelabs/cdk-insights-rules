import type { Rule } from '../../types';

/**
 * sns-encryption-disabled
 *
 * SNS topics are not encrypted at rest by default: without a KmsMasterKeyId,
 * messages sit unencrypted in the topic. (Unlike SQS, SNS has no
 * service-managed default encryption.)
 */
export const snsEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'sns-encryption-disabled',
    name: 'SNS Encryption Disabled',
    description:
      'Detects SNS topics without a KMS master key, leaving messages unencrypted at rest.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::SNS::Topic'],
    awsDocUrl:
      'https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html',
    remediationSteps: [
      'Set KmsMasterKeyId (e.g. alias/aws/sns, or a customer-managed key for cross-service publishing)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::SNS::Topic' &&
        !resource.Properties?.KmsMasterKeyId
      ) {
        report(resourceId, {
          issue: 'SNS topic is not encrypted at rest (no KmsMasterKeyId).',
          recommendation:
            'Set KmsMasterKeyId — alias/aws/sns for the AWS-managed key, or a customer-managed key when other services must publish to the topic.',
        });
      }
    }
  },

  example: {
    flagged: `import * as sns from 'aws-cdk-lib/aws-sns';

new sns.CfnTopic(this, 'Topic', {});`,
    fixed: `import * as sns from 'aws-cdk-lib/aws-sns';

new sns.CfnTopic(this, 'Topic', {
  kmsMasterKeyId: 'alias/aws/sns',
});`,
  },
};
