import { isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * kinesis-encryption-disabled
 *
 * A Kinesis data stream without StreamEncryption stores records unencrypted.
 * An intrinsic StreamEncryption value is undecidable and never flagged.
 */
export const kinesisEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'kinesis-encryption-disabled',
    name: 'Kinesis Encryption Disabled',
    description:
      'Detects Kinesis data streams without server-side encryption enabled.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Kinesis::Stream'],
    awsDocUrl:
      'https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html',
    remediationSteps: [
      'Set StreamEncryption with EncryptionType KMS and a KeyId (e.g. alias/aws/kinesis or a customer-managed key)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Kinesis::Stream') {
        continue;
      }
      const encryption = resource.Properties?.StreamEncryption;
      if (isIntrinsic(encryption)) {
        continue;
      }
      const encryptionType = encryption?.EncryptionType;
      if (!encryptionType || encryptionType === 'NONE') {
        report(resourceId, {
          issue:
            'Kinesis data stream does not have server-side encryption enabled.',
          recommendation:
            'Set StreamEncryption with EncryptionType KMS to protect records at rest.',
        });
      }
    }
  },

  example: {
    flagged: `import * as kinesis from 'aws-cdk-lib/aws-kinesis';

new kinesis.CfnStream(this, 'Stream', {
  shardCount: 1,
});`,
    fixed: `import * as kinesis from 'aws-cdk-lib/aws-kinesis';

new kinesis.CfnStream(this, 'Stream', {
  shardCount: 1,
  streamEncryption: {
    encryptionType: 'KMS',
    keyId: 'alias/aws/kinesis',
  },
});`,
  },
};
