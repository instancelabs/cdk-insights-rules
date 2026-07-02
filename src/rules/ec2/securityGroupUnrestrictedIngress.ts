import type { Rule } from '../../types';

/** Ports whose exposure to the internet is a near-certain incident. */
const DANGEROUS_PORTS: Record<number, string> = {
  22: 'SSH',
  3389: 'RDP',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  1433: 'MSSQL',
  27017: 'MongoDB',
  6379: 'Redis',
};

interface IngressRule {
  CidrIp?: unknown;
  CidrIpv6?: unknown;
  IpProtocol?: unknown;
  FromPort?: unknown;
  ToPort?: unknown;
}

const isOpenToInternet = (rule: IngressRule): boolean =>
  rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0';

const isAllTraffic = (protocol: unknown): boolean =>
  protocol === '-1' || protocol === -1;

const isTcp = (protocol: unknown): boolean =>
  protocol === 'tcp' || protocol === '6' || protocol === 6;

/** Names of dangerous services exposed by an internet-open ingress rule. */
const exposedDangerousServices = (rule: IngressRule): string[] => {
  if (isAllTraffic(rule.IpProtocol)) {
    return ['all ports'];
  }
  if (!isTcp(rule.IpProtocol)) {
    return [];
  }
  const from = typeof rule.FromPort === 'number' ? rule.FromPort : undefined;
  const to = typeof rule.ToPort === 'number' ? rule.ToPort : undefined;
  if (from === undefined || to === undefined) {
    return [];
  }
  return Object.entries(DANGEROUS_PORTS)
    .filter(([port]) => Number(port) >= from && Number(port) <= to)
    .map(([port, service]) => `${service} (${port})`);
};

/**
 * security-group-unrestricted-ingress
 *
 * An ingress rule open to 0.0.0.0/0 or ::/0 exposes whatever is behind the
 * security group to the entire internet. The finding calls out management and
 * database ports (SSH, RDP, MySQL, ...) explicitly, since those are the ones
 * that get boxes compromised within hours. Inspects both inline
 * SecurityGroupIngress rules and standalone AWS::EC2::SecurityGroupIngress
 * resources.
 */
export const securityGroupUnrestrictedIngress: Rule = {
  metadata: {
    ruleId: 'security-group-unrestricted-ingress',
    name: 'Security Group Unrestricted Ingress',
    description:
      'Detects security group ingress rules open to the whole internet (0.0.0.0/0 or ::/0).',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::EC2::SecurityGroup',
      'AWS::EC2::SecurityGroupIngress',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    remediationSteps: [
      'Restrict ingress to specific CIDR ranges or security group references',
      'For management ports (SSH/RDP), use SSM Session Manager, a bastion host, or VPN instead of public exposure',
      'If public ingress is intentional (e.g. 80/443 on a load balancer), suppress this rule on the resource',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    const flag = (resourceId: string, rules: IngressRule[]): void => {
      const open = rules.filter(isOpenToInternet);
      if (open.length === 0) {
        return;
      }
      const dangerous = open.flatMap(exposedDangerousServices);
      const detail = dangerous.length
        ? ` — including ${[...new Set(dangerous)].join(', ')}`
        : '';
      report(resourceId, {
        issue: `Security group allows unrestricted ingress from the internet (0.0.0.0/0 or ::/0)${detail}.`,
        recommendation:
          'Restrict the ingress rule to specific CIDR ranges or security group references; use SSM Session Manager, a bastion, or VPN for management access instead of exposing ports publicly.',
      });
    };

    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type === 'AWS::EC2::SecurityGroup') {
        const ingress = resource.Properties?.SecurityGroupIngress;
        flag(resourceId, Array.isArray(ingress) ? ingress : []);
      }
      if (resource.Type === 'AWS::EC2::SecurityGroupIngress') {
        flag(resourceId, [resource.Properties ?? {}]);
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'Sg', {
  groupDescription: 'app servers',
  securityGroupIngress: [
    { ipProtocol: 'tcp', fromPort: 22, toPort: 22, cidrIp: '0.0.0.0/0' },
  ],
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnSecurityGroup(this, 'Sg', {
  groupDescription: 'app servers',
  securityGroupIngress: [
    { ipProtocol: 'tcp', fromPort: 22, toPort: 22, cidrIp: '10.0.0.0/16' },
  ],
});`,
  },
};
