import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * sqs-encryption-disabled
 *
 * SQS has applied SSE-SQS to newly created queues by default since late 2022,
 * so an *absent* encryption property is a secure default and must not be
 * flagged. The only decidable violation is explicitly opting out:
 * `SqsManagedSseEnabled: false` with no KMS key. (The CDK Insights product
 * historically flagged absence too — this port deliberately tightens that to
 * honour the low-false-positive contract.)
 */
export const sqsEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'sqs-encryption-disabled',
    name: 'SQS Encryption Explicitly Disabled',
    description:
      'Detects SQS queues that explicitly disable server-side encryption (SqsManagedSseEnabled: false) without providing a KMS key.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::SQS::Queue'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html',
    remediationSteps: [
      'Remove SqsManagedSseEnabled: false so the SSE-SQS default applies',
      'Or set KmsMasterKeyId for a customer-managed key',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::SQS::Queue') {
        continue;
      }
      const props = resource.Properties ?? {};
      if (
        asBoolean(props.SqsManagedSseEnabled) === false &&
        !props.KmsMasterKeyId
      ) {
        report(resourceId, {
          issue:
            'SQS queue explicitly disables server-side encryption (SqsManagedSseEnabled: false) with no KMS key configured.',
          recommendation:
            'Remove SqsManagedSseEnabled: false to keep the SSE-SQS default, or set KmsMasterKeyId for a customer-managed key.',
        });
      }
    }
  },

  example: {
    flagged: `import * as sqs from 'aws-cdk-lib/aws-sqs';

new sqs.CfnQueue(this, 'Queue', {
  sqsManagedSseEnabled: false,
});`,
    fixed: `import * as sqs from 'aws-cdk-lib/aws-sqs';

new sqs.CfnQueue(this, 'Queue', {
  kmsMasterKeyId: 'alias/aws/sqs',
});`,
  },
};
