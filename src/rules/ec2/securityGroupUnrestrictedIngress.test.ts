import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { securityGroupUnrestrictedIngress } from './securityGroupUnrestrictedIngress';

describe('security-group-unrestricted-ingress', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [securityGroupUnrestrictedIngress]);

  it('flags IPv4-open ingress and names the dangerous service', () => {
    const findings = run({
      Resources: {
        Sg: {
          Type: 'AWS::EC2::SecurityGroup',
          Properties: {
            GroupDescription: 'x',
            SecurityGroupIngress: [
              {
                IpProtocol: 'tcp',
                FromPort: 22,
                ToPort: 22,
                CidrIp: '0.0.0.0/0',
              },
            ],
          },
        },
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('SSH (22)');
  });

  it('flags IPv6-open ingress and all-traffic rules', () => {
    const findings = run({
      Resources: {
        V6: {
          Type: 'AWS::EC2::SecurityGroup',
          Properties: {
            GroupDescription: 'x',
            SecurityGroupIngress: [
              {
                IpProtocol: 'tcp',
                FromPort: 443,
                ToPort: 443,
                CidrIpv6: '::/0',
              },
            ],
          },
        },
        AllTraffic: {
          Type: 'AWS::EC2::SecurityGroup',
          Properties: {
            GroupDescription: 'x',
            SecurityGroupIngress: [{ IpProtocol: '-1', CidrIp: '0.0.0.0/0' }],
          },
        },
      },
    });

    expect(findings.map((finding) => finding.resourceId).sort()).toEqual([
      'AllTraffic',
      'V6',
    ]);
    expect(
      findings.find((finding) => finding.resourceId === 'AllTraffic')?.issue
    ).toContain('all ports');
  });

  it('flags a standalone SecurityGroupIngress resource', () => {
    expect(
      run({
        Resources: {
          Ingress: {
            Type: 'AWS::EC2::SecurityGroupIngress',
            Properties: {
              GroupId: 'sg-123',
              IpProtocol: 'tcp',
              FromPort: 3306,
              ToPort: 3306,
              CidrIp: '0.0.0.0/0',
            },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag restricted CIDRs or SG references', () => {
    expect(
      run({
        Resources: {
          Sg: {
            Type: 'AWS::EC2::SecurityGroup',
            Properties: {
              GroupDescription: 'x',
              SecurityGroupIngress: [
                {
                  IpProtocol: 'tcp',
                  FromPort: 22,
                  ToPort: 22,
                  CidrIp: '10.0.0.0/16',
                },
                {
                  IpProtocol: 'tcp',
                  FromPort: 5432,
                  ToPort: 5432,
                  SourceSecurityGroupId: 'sg-456',
                },
              ],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
