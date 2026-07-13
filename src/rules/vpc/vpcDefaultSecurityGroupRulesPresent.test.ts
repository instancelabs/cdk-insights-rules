import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { vpcDefaultSecurityGroupRulesPresent } from './vpcDefaultSecurityGroupRulesPresent';

describe('vpc-default-security-group-rules-present', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [vpcDefaultSecurityGroupRulesPresent]);

  const standaloneRule = (
    type: 'Ingress' | 'Egress',
    groupId: unknown
  ): CfnTemplate => ({
    Resources: {
      Vpc: { Type: 'AWS::EC2::VPC', Properties: { CidrBlock: '10.0.0.0/16' } },
      TheRule: {
        Type: `AWS::EC2::SecurityGroup${type}`,
        Properties: { GroupId: groupId, IpProtocol: 'tcp' },
      },
    },
  });

  it('flags standalone rules attached to the VPC default security group', () => {
    expect(
      run(
        standaloneRule('Ingress', {
          'Fn::GetAtt': ['Vpc', 'DefaultSecurityGroup'],
        })
      )
    ).toHaveLength(1);
    expect(
      run(
        standaloneRule('Egress', { 'Fn::GetAtt': 'Vpc.DefaultSecurityGroup' })
      )
    ).toHaveLength(1);
  });

  it('does not flag rules attached to purpose-built groups', () => {
    expect(
      run(standaloneRule('Ingress', { 'Fn::GetAtt': ['AppSg', 'GroupId'] }))
    ).toHaveLength(0);
    expect(run(standaloneRule('Ingress', { Ref: 'AppSg' }))).toHaveLength(0);
    expect(run(standaloneRule('Ingress', 'sg-0123456789abcdef0'))).toHaveLength(
      0
    );
  });

  it('does not flag inline rules on an AWS::EC2::SecurityGroup resource', () => {
    expect(
      run({
        Resources: {
          AppSg: {
            Type: 'AWS::EC2::SecurityGroup',
            Properties: {
              GroupDescription: 'x',
              SecurityGroupIngress: [{ IpProtocol: 'tcp' }],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
