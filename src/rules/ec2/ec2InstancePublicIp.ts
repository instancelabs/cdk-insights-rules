import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ec2-instance-public-ip
 *
 * `AssociatePublicIpAddress: true` on an instance network interface puts the
 * instance directly on the internet. Workloads belong in private subnets with
 * a NAT gateway for outbound and a load balancer for inbound. Only a decidable
 * `true` is flagged.
 */
export const ec2InstancePublicIp: Rule = {
  metadata: {
    ruleId: 'ec2-instance-public-ip',
    name: 'EC2 Instance Public IP',
    description:
      'Detects EC2 instances whose NetworkInterfaces set AssociatePublicIpAddress to true, exposing the instance directly to the internet.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EC2::Instance'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html',
    remediationSteps: [
      'Set AssociatePublicIpAddress to false on the network interface',
      'Place the instance in a private subnet and use a NAT gateway / VPC endpoints for outbound traffic',
      'Front the workload with an ALB/NLB in a public subnet instead',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EC2::Instance') {
        continue;
      }
      const interfaces = resource.Properties?.NetworkInterfaces;
      if (!Array.isArray(interfaces)) {
        continue;
      }
      if (
        interfaces.some(
          (networkInterface) =>
            asBoolean(networkInterface?.AssociatePublicIpAddress) === true
        )
      ) {
        report(resourceId, {
          issue:
            'EC2 instance has a network interface with AssociatePublicIpAddress set to true, making it directly internet-reachable.',
          recommendation:
            'Set AssociatePublicIpAddress to false and place the instance in a private subnet; use a NAT gateway for outbound and a load balancer for inbound traffic.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnInstance(this, 'Instance', {
  imageId: 'ami-1234567890abcdef0',
  instanceType: 't3.micro',
  networkInterfaces: [
    { deviceIndex: '0', associatePublicIpAddress: true },
  ],
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnInstance(this, 'Instance', {
  imageId: 'ami-1234567890abcdef0',
  instanceType: 't3.micro',
  networkInterfaces: [
    { deviceIndex: '0', associatePublicIpAddress: false },
  ],
});`,
  },
};
