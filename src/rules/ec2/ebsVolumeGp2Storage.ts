import type { Rule } from '../../types';

/**
 * ebs-volume-gp2-storage
 *
 * gp3 delivers gp2's baseline performance at ~20% lower cost with
 * independently provisioned IOPS/throughput.
 */
export const ebsVolumeGp2Storage: Rule = {
  metadata: {
    ruleId: 'ebs-volume-gp2-storage',
    name: 'EBS Volume On gp2 Storage',
    description:
      'Detects EBS volumes using gp2 where gp3 offers the same baseline for less.',
    severity: 'LOW',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::EC2::Volume'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/general-purpose.html',
    remediationSteps: [
      'Set VolumeType to gp3 (and tune IOPS/Throughput independently if needed)',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::EC2::Volume' &&
        resource.Properties?.VolumeType === 'gp2'
      ) {
        report(resourceId, {
          issue: 'EBS volume uses gp2 storage.',
          recommendation:
            'Switch to gp3 — same baseline performance at lower cost, with IOPS and throughput tunable independently.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnVolume(this, 'Volume', {
  availabilityZone: 'eu-west-2a',
  size: 100,
  encrypted: true,
  volumeType: 'gp2',
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnVolume(this, 'Volume', {
  availabilityZone: 'eu-west-2a',
  size: 100,
  encrypted: true,
  volumeType: 'gp3',
});`,
  },
};
