import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * autoscaling-launch-config-public-ip
 *
 * A launch configuration with `AssociatePublicIpAddress: true` puts every
 * instance the group launches directly on the internet. Only a decidable
 * `true` is flagged.
 */
export const autoscalingLaunchConfigPublicIp: Rule = {
  metadata: {
    ruleId: 'autoscaling-launch-config-public-ip',
    name: 'AutoScaling Launch Configuration Public IP',
    description:
      'Detects AutoScaling launch configurations that associate a public IP with every launched instance.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::AutoScaling::LaunchConfiguration'],
    awsDocUrl:
      'https://docs.aws.amazon.com/autoscaling/ec2/userguide/AutoScalingGroupExamples.html',
    remediationSteps: [
      'Set AssociatePublicIpAddress to false and launch into private subnets',
      'Front the group with a load balancer and use a NAT gateway for outbound traffic',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::AutoScaling::LaunchConfiguration' &&
        asBoolean(resource.Properties?.AssociatePublicIpAddress) === true
      ) {
        report(resourceId, {
          issue:
            'AutoScaling launch configuration associates a public IP with every launched instance.',
          recommendation:
            'Set AssociatePublicIpAddress to false and place instances in private subnets behind a load balancer.',
        });
      }
    }
  },

  example: {
    flagged: `import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';

new autoscaling.CfnLaunchConfiguration(this, 'LaunchConfig', {
  imageId: 'ami-1234567890abcdef0',
  instanceType: 't3.micro',
  associatePublicIpAddress: true,
});`,
    fixed: `import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';

new autoscaling.CfnLaunchConfiguration(this, 'LaunchConfig', {
  imageId: 'ami-1234567890abcdef0',
  instanceType: 't3.micro',
  associatePublicIpAddress: false,
});`,
  },
};
