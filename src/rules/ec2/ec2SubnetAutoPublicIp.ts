import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ec2-subnet-auto-public-ip
 *
 * A subnet with MapPublicIpOnLaunch hands every instance launched into it a
 * public IP by default. Advisory: public subnets in a standard VPC layout
 * legitimately set this (the CDK Vpc construct does for PUBLIC subnets), so
 * this rule is LOW — it exists to make the blast radius visible, not to
 * fail builds. (The product ships it as MEDIUM; the open catalog downgrades
 * it because it fires on default CDK VPCs.)
 */
export const ec2SubnetAutoPublicIp: Rule = {
  metadata: {
    ruleId: 'ec2-subnet-auto-public-ip',
    name: 'EC2 Subnet Auto-Assigns Public IPs',
    description:
      'Detects subnets that auto-assign public IPs to launched instances (MapPublicIpOnLaunch).',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EC2::Subnet'],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html#subnet-public-ip',
    remediationSteps: [
      'Set MapPublicIpOnLaunch to false unless the subnet is intentionally public',
      'Prefer opting into public IPs per instance/ENI rather than inheriting them from the subnet',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::EC2::Subnet' &&
        asBoolean(resource.Properties?.MapPublicIpOnLaunch) === true
      ) {
        report(resourceId, {
          issue:
            'Subnet auto-assigns public IPs to launched instances (MapPublicIpOnLaunch is true).',
          recommendation:
            'Keep MapPublicIpOnLaunch false unless this is intentionally a public subnet; let workloads opt into public IPs at the ENI level.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSubnet(this, 'Subnet', {
  vpcId: 'vpc-12345678',
  cidrBlock: '10.0.1.0/24',
  mapPublicIpOnLaunch: true,
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSubnet(this, 'Subnet', {
  vpcId: 'vpc-12345678',
  cidrBlock: '10.0.1.0/24',
  mapPublicIpOnLaunch: false,
});`,
  },
};
