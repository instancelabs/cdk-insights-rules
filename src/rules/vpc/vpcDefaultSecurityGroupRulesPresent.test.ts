import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { vpcDefaultSecurityGroupRulesPresent } from './vpcDefaultSecurityGroupRulesPresent';

describe('vpc-default-security-group-rules-present', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [vpcDefaultSecurityGroupRulesPresent]);

  const sg = (name: string, rules: object): CfnTemplate => ({
    Resources: {
      Sg: {
        Type: 'AWS::EC2::SecurityGroup',
        Properties: { GroupName: name, GroupDescription: 'x', ...rules },
      },
    },
  });

  it('flags a default security group with rules', () => {
    expect(
      run(sg('default', { SecurityGroupIngress: [{ IpProtocol: 'tcp' }] }))
    ).toHaveLength(1);
    expect(
      run(sg('default', { SecurityGroupEgress: [{ IpProtocol: '-1' }] }))
    ).toHaveLength(1);
  });

  it('does not flag a ruleless default group or a named group with rules', () => {
    expect(run(sg('default', {}))).toHaveLength(0);
    expect(
      run(sg('app', { SecurityGroupIngress: [{ IpProtocol: 'tcp' }] }))
    ).toHaveLength(0);
  });
});
