import type { Rule } from '../../types';

/**
 * security-group-unrestricted-egress
 *
 * Advisory: allow-all egress is CDK's own default (allowAllOutbound), so
 * this is LOW by design — it exists to make the choice visible for
 * defence-in-depth environments (egress filtering, exfiltration controls),
 * not to fail builds.
 */
export const securityGroupUnrestrictedEgress: Rule = {
  metadata: {
    ruleId: 'security-group-unrestricted-egress',
    name: 'Security Group Unrestricted Egress',
    description:
      'Detects security groups with egress open to the whole internet (0.0.0.0/0).',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    remediationSteps: [
      'For defence-in-depth environments, restrict egress to specific destinations (in CDK: allowAllOutbound: false plus explicit egress rules)',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EC2::SecurityGroup') {
        continue;
      }
      const egress = resource.Properties?.SecurityGroupEgress;
      if (
        Array.isArray(egress) &&
        egress.some(
          (rule) => rule?.CidrIp === '0.0.0.0/0' || rule?.CidrIpv6 === '::/0'
        )
      ) {
        report(resourceId, {
          issue:
            'Security group allows unrestricted egress to the internet (0.0.0.0/0).',
          recommendation:
            'Where egress filtering matters (exfiltration controls, compliance), restrict outbound rules to specific destinations; otherwise suppress — allow-all outbound is the CDK default.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'Sg', {
  groupDescription: 'app servers',
  securityGroupIngress: [
    { ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/16' },
  ],
  securityGroupEgress: [{ ipProtocol: '-1', cidrIp: '0.0.0.0/0' }],
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'Sg', {
  groupDescription: 'app servers',
  securityGroupIngress: [
    { ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/16' },
  ],
  securityGroupEgress: [
    { ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/16' },
  ],
});`,
  },
};
