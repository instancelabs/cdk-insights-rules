import type { Rule } from '../../types';

/**
 * vpc-default-security-group-rules-present
 *
 * CIS AWS Foundations: the default security group must have no rules —
 * resources should use purpose-built groups. Flags security groups named
 * "default" that define ingress or egress rules.
 */
export const vpcDefaultSecurityGroupRulesPresent: Rule = {
  metadata: {
    ruleId: 'vpc-default-security-group-rules-present',
    name: 'VPC Default Security Group Has Rules',
    description:
      'Detects default security groups with ingress or egress rules configured.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/default-security-group.html',
    remediationSteps: [
      'Remove all rules from the default security group and use purpose-built security groups (in CDK: restrictDefaultSecurityGroup: true)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EC2::SecurityGroup') {
        continue;
      }
      if (resource.Properties?.GroupName !== 'default') {
        continue;
      }
      const ingress = resource.Properties?.SecurityGroupIngress;
      const egress = resource.Properties?.SecurityGroupEgress;
      if (
        (Array.isArray(ingress) && ingress.length > 0) ||
        (Array.isArray(egress) && egress.length > 0)
      ) {
        report(resourceId, {
          issue: 'VPC default security group has rules configured.',
          recommendation:
            'Remove all rules from the default security group; resources should use purpose-built groups (CIS AWS Foundations).',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'DefaultSg', {
  groupName: 'default',
  groupDescription: 'default VPC security group',
  securityGroupIngress: [
    { ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/16' },
  ],
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'AppSg', {
  groupName: 'app-servers',
  groupDescription: 'purpose-built group for app servers',
  securityGroupIngress: [
    { ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/16' },
  ],
});`,
  },
};
