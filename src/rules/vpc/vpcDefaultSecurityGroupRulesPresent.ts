import type { Rule } from '../../types';

/**
 * vpc-default-security-group-rules-present
 *
 * CIS AWS Foundations: the default security group must have no rules —
 * resources should use purpose-built groups.
 *
 * The default SG is created by EC2 alongside the VPC and never appears as an
 * AWS::EC2::SecurityGroup resource in a template ("default" is a reserved
 * group name CloudFormation cannot create). The template-visible way to add
 * rules to it is a standalone AWS::EC2::SecurityGroupIngress/Egress resource
 * whose GroupId is Fn::GetAtt [Vpc, DefaultSecurityGroup] — which is exactly
 * what this rule detects.
 */

/** True when a GroupId value resolves to a VPC's DefaultSecurityGroup attribute. */
// biome-ignore lint/suspicious/noExplicitAny: templates are arbitrary JSON
const referencesDefaultSecurityGroup = (groupId: any): boolean => {
  const getAtt = groupId?.['Fn::GetAtt'];
  if (Array.isArray(getAtt)) {
    return getAtt[1] === 'DefaultSecurityGroup';
  }
  if (typeof getAtt === 'string') {
    return getAtt.endsWith('.DefaultSecurityGroup');
  }
  return false;
};

export const vpcDefaultSecurityGroupRulesPresent: Rule = {
  metadata: {
    ruleId: 'vpc-default-security-group-rules-present',
    name: 'VPC Default Security Group Has Rules',
    description:
      'Detects standalone security group rules attached to a VPC default security group (GroupId referencing Fn::GetAtt DefaultSecurityGroup). CIS requires the default group to have no rules.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::EC2::SecurityGroupIngress',
      'AWS::EC2::SecurityGroupEgress',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/default-security-group.html',
    remediationSteps: [
      'Attach rules to a purpose-built security group instead of the VPC default group',
      'In CDK, leave the default group untouched and enable restrictDefaultSecurityGroup: true on the Vpc so its out-of-the-box rules are removed',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type !== 'AWS::EC2::SecurityGroupIngress' &&
        resource.Type !== 'AWS::EC2::SecurityGroupEgress'
      ) {
        continue;
      }
      if (!referencesDefaultSecurityGroup(resource.Properties?.GroupId)) {
        continue;
      }
      report(resourceId, {
        issue:
          'Security group rule is attached to the VPC default security group.',
        recommendation:
          'Move the rule to a purpose-built security group; CIS AWS Foundations requires the default group to have no rules (in CDK, also set restrictDefaultSecurityGroup: true on the Vpc).',
      });
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

const vpc = new ec2.Vpc(this, 'Vpc', { maxAzs: 2, natGateways: 0 });

new ec2.CfnSecurityGroupIngress(this, 'DefaultSgIngress', {
  groupId: vpc.vpcDefaultSecurityGroup,
  ipProtocol: 'tcp',
  fromPort: 443,
  toPort: 443,
  cidrIp: '10.0.0.0/16',
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

const vpc = new ec2.Vpc(this, 'Vpc', { maxAzs: 2, natGateways: 0 });

const appSg = new ec2.SecurityGroup(this, 'AppSg', {
  vpc,
  description: 'purpose-built group for app servers',
  allowAllOutbound: false,
});
appSg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(443));`,
  },
};
