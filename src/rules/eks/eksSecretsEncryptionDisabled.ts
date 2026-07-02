import type { Rule } from '../../types';

/**
 * eks-secrets-encryption-disabled
 *
 * Without an EncryptionConfig covering `secrets`, Kubernetes secrets sit in
 * etcd protected only by the default EBS-layer encryption — envelope
 * encryption with your own KMS key is the EKS security baseline.
 */
export const eksSecretsEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'eks-secrets-encryption-disabled',
    name: 'EKS Secrets Encryption Disabled',
    description:
      'Detects EKS clusters without KMS envelope encryption for Kubernetes secrets.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EKS::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html',
    remediationSteps: [
      'Add EncryptionConfig with Resources: ["secrets"] and a KMS key (in CDK: secretsEncryptionKey)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EKS::Cluster') {
        continue;
      }
      const encryptionConfig = resource.Properties?.EncryptionConfig;
      const hasSecretsEncryption =
        Array.isArray(encryptionConfig) &&
        encryptionConfig.some(
          (config) =>
            Array.isArray(config?.Resources) &&
            config.Resources.includes('secrets')
        );
      if (!hasSecretsEncryption) {
        report(resourceId, {
          issue:
            'EKS cluster does not have KMS envelope encryption enabled for Kubernetes secrets.',
          recommendation:
            'Configure EncryptionConfig with Resources ["secrets"] and a KMS key so secrets in etcd are envelope-encrypted.',
        });
      }
    }
  },

  example: {
    flagged: `import * as eks from 'aws-cdk-lib/aws-eks';

new eks.CfnCluster(this, 'Cluster', {
  roleArn: 'arn:aws:iam::111122223333:role/eks-cluster-role',
  resourcesVpcConfig: {
    subnetIds: ['subnet-12345678', 'subnet-87654321'],
  },
});`,
    fixed: `import * as eks from 'aws-cdk-lib/aws-eks';

new eks.CfnCluster(this, 'Cluster', {
  roleArn: 'arn:aws:iam::111122223333:role/eks-cluster-role',
  resourcesVpcConfig: {
    subnetIds: ['subnet-12345678', 'subnet-87654321'],
  },
  encryptionConfig: [
    {
      resources: ['secrets'],
      provider: {
        keyArn:
          'arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
      },
    },
  ],
});`,
  },
};
