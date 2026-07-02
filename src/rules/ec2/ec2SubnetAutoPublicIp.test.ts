import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ec2SubnetAutoPublicIp } from './ec2SubnetAutoPublicIp';

describe('ec2-subnet-auto-public-ip', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ec2SubnetAutoPublicIp]);

  const subnet = (properties: object): CfnTemplate => ({
    Resources: {
      Subnet: { Type: 'AWS::EC2::Subnet', Properties: properties },
    },
  });

  it('flags MapPublicIpOnLaunch true (boolean or string form)', () => {
    expect(run(subnet({ MapPublicIpOnLaunch: true }))).toHaveLength(1);
    expect(run(subnet({ MapPublicIpOnLaunch: 'true' }))).toHaveLength(1);
  });

  it('does not flag false, absent, or intrinsic values', () => {
    expect(run(subnet({ MapPublicIpOnLaunch: false }))).toHaveLength(0);
    expect(run(subnet({}))).toHaveLength(0);
    expect(
      run(subnet({ MapPublicIpOnLaunch: { 'Fn::If': ['X', true, false] } }))
    ).toHaveLength(0);
  });
});
