import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * msk-encryption-weak
 *
 * MSK defaults to TLS everywhere; this flags explicit weakening — allowing
 * plaintext client-broker traffic, or disabling inter-broker encryption.
 * (The product also nudges toward a customer-managed at-rest key; that is an
 * advisory-severity concern and deliberately not part of this HIGH rule.)
 */
export const mskEncryptionWeak: Rule = {
  metadata: {
    ruleId: 'msk-encryption-weak',
    name: 'MSK Encryption Weakened',
    description:
      'Detects MSK clusters that allow plaintext client-broker traffic or disable inter-broker encryption.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::MSK::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html',
    remediationSteps: [
      'Set EncryptionInTransit.ClientBroker to TLS',
      'Keep EncryptionInTransit.InCluster true (the default)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::MSK::Cluster') {
        continue;
      }
      const inTransit =
        resource.Properties?.EncryptionInfo?.EncryptionInTransit;
      const clientBroker = inTransit?.ClientBroker;
      if (clientBroker === 'PLAINTEXT' || clientBroker === 'TLS_PLAINTEXT') {
        report(resourceId, {
          issue: `MSK cluster allows unencrypted client-broker communication (ClientBroker: ${clientBroker}).`,
          recommendation:
            'Set ClientBroker to TLS so all client traffic to the brokers is encrypted.',
        });
      }
      if (asBoolean(inTransit?.InCluster) === false) {
        report(resourceId, {
          issue:
            'MSK cluster disables encryption for inter-broker communication (InCluster: false).',
          recommendation:
            'Remove InCluster: false so broker-to-broker replication traffic stays encrypted.',
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
  encryptionInfo: {
    encryptionInTransit: { clientBroker: 'PLAINTEXT' },
  },
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
  encryptionInfo: {
    encryptionInTransit: { clientBroker: 'TLS' },
  },
});`,
  },
};
