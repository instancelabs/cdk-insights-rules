import type { Rule } from '../../types';

/**
 * security-group-no-rules
 *
 * A security group with neither ingress nor egress rules is usually an
 * orphan — left behind by a refactor, or created and never wired up.
 */
export const securityGroupNoRules: Rule = {
  metadata: {
    ruleId: 'security-group-no-rules',
    name: 'Security Group Has No Rules',
    description:
      'Detects security groups with no ingress or egress rules defined.',
    severity: 'LOW',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    remediationSteps: [
      'Add the intended rules, or delete the group if it is orphaned',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EC2::SecurityGroup') {
        continue;
      }
      const props = resource.Properties ?? {};
      const ingress = props.SecurityGroupIngress;
      const egress = props.SecurityGroupEgress;
      const hasIngress = Array.isArray(ingress) && ingress.length > 0;
      const hasEgress = Array.isArray(egress) && egress.length > 0;
      if (!hasIngress && !hasEgress) {
        report(resourceId, {
          issue: 'Security group has no ingress or egress rules defined.',
          recommendation:
            'Review whether this group is still needed — empty groups usually indicate orphaned resources or unfinished wiring.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'Sg', {
  groupDescription: 'app servers',
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'Sg', {
  groupDescription: 'app servers',
  securityGroupIngress: [
    { ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/16' },
  ],
});`,
  },
};
