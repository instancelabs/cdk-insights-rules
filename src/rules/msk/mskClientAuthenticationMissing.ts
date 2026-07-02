import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * msk-client-authentication-missing
 *
 * An MSK cluster with no client authentication (no SASL/SCRAM, no IAM, no
 * mutual TLS) — or with unauthenticated access explicitly enabled — accepts
 * connections from anything that can reach the brokers.
 */
export const mskClientAuthenticationMissing: Rule = {
  metadata: {
    ruleId: 'msk-client-authentication-missing',
    name: 'MSK Client Authentication Missing',
    description:
      'Detects MSK clusters with no client authentication configured, or with unauthenticated access enabled.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::MSK::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/msk/latest/developerguide/kafka_apis_iam.html',
    remediationSteps: [
      'Enable IAM authentication (ClientAuthentication.Sasl.Iam) or SASL/SCRAM, or mutual TLS via a certificate authority',
      'Do not enable Unauthenticated access',
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
      const auth = resource.Properties?.ClientAuthentication;
      const hasTls =
        Array.isArray(auth?.Tls?.CertificateAuthorityArnList) &&
        auth.Tls.CertificateAuthorityArnList.length > 0;
      const hasSasl =
        asBoolean(auth?.Sasl?.Scram?.Enabled) === true ||
        asBoolean(auth?.Sasl?.Iam?.Enabled) === true;

      if (!hasTls && !hasSasl) {
        report(resourceId, {
          issue: 'MSK cluster has no client authentication configured.',
          recommendation:
            'Enable IAM authentication, SASL/SCRAM, or mutual TLS so only authenticated clients can connect to the brokers.',
        });
      }
      if (asBoolean(auth?.Unauthenticated?.Enabled) === true) {
        report(resourceId, {
          issue: 'MSK cluster explicitly allows unauthenticated access.',
          recommendation:
            'Disable Unauthenticated access and require client authentication for every connection.',
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
  clientAuthentication: {
    sasl: { iam: { enabled: true } },
  },
});`,
  },
};
