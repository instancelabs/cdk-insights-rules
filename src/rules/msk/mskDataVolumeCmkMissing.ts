import type { Rule } from '../../types';

/**
 * msk-data-volume-cmk-missing
 *
 * MSK encrypts broker volumes with an AWS-managed key by default; a
 * customer-managed key adds key-policy scoping and rotation audit.
 * Advisory (LOW) — the default is encrypted, just not customer-controlled.
 */
export const mskDataVolumeCmkMissing: Rule = {
  metadata: {
    ruleId: 'msk-data-volume-cmk-missing',
    name: 'MSK Data Volume CMK Missing',
    description:
      'Detects MSK clusters whose broker volumes are not encrypted with a customer-managed KMS key.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::MSK::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html',
    remediationSteps: [
      'Set EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId to a customer-managed key',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::MSK::Cluster') {
        continue;
      }
      if (
        !resource.Properties?.EncryptionInfo?.EncryptionAtRest
          ?.DataVolumeKMSKeyId
      ) {
        report(resourceId, {
          issue:
            'MSK cluster does not use a customer-managed KMS key for encryption at rest (AWS-managed default applies).',
          recommendation:
            'Set EncryptionAtRest.DataVolumeKMSKeyId to a customer-managed key where key control must be auditable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as msk from 'aws-cdk-lib/aws-msk';

new msk.CfnCluster(this, 'Cluster', {
  clusterName: 'events',
  kafkaVersion: '3.6.0',
  numberOfBrokerNodes: 2,
  brokerNodeGroupInfo: {
    clientSubnets: ['subnet-12345678', 'subnet-87654321'],
    instanceType: 'kafka.m5.large',
  },
  clientAuthentication: { sasl: { iam: { enabled: true } } },
});`,
    fixed: `import * as msk from 'aws-cdk-lib/aws-msk';

new msk.CfnCluster(this, 'Cluster', {
  clusterName: 'events',
  kafkaVersion: '3.6.0',
  numberOfBrokerNodes: 2,
  brokerNodeGroupInfo: {
    clientSubnets: ['subnet-12345678', 'subnet-87654321'],
    instanceType: 'kafka.m5.large',
  },
  clientAuthentication: { sasl: { iam: { enabled: true } } },
  encryptionInfo: {
    encryptionAtRest: {
      dataVolumeKmsKeyId:
        'arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    },
  },
});`,
  },
};
