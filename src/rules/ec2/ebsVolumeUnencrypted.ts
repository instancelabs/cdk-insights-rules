import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ebs-volume-unencrypted
 *
 * An unencrypted EBS volume leaves data at rest readable if the volume or a
 * snapshot of it leaks. Encryption must be chosen at creation time. Values set
 * via intrinsics are undecidable and never flagged.
 */
export const ebsVolumeUnencrypted: Rule = {
  metadata: {
    ruleId: 'ebs-volume-unencrypted',
    name: 'EBS Volume Unencrypted',
    description: 'Detects EBS volumes without encryption at rest.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EC2::Volume'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    remediationSteps: [
      'Set Encrypted to true on the volume (optionally with a KmsKeyId customer-managed key)',
      'Enable EBS encryption by default in the account settings as a backstop',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EC2::Volume') {
        continue;
      }
      const encrypted = resource.Properties?.Encrypted;
      if (isIntrinsic(encrypted) || asBoolean(encrypted) === true) {
        continue;
      }
      report(resourceId, {
        issue: 'EBS volume is not encrypted.',
        recommendation:
          'Set Encrypted to true (optionally with a customer-managed KmsKeyId) to protect data at rest — encryption cannot be added to an existing volume.',
      });
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnVolume(this, 'Volume', {
  availabilityZone: 'eu-west-2a',
  size: 10,
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnVolume(this, 'Volume', {
  availabilityZone: 'eu-west-2a',
  size: 10,
  encrypted: true,
});`,
  },
};
