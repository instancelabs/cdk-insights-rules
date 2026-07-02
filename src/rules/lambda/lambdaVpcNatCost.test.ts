import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaVpcNatCost } from './lambdaVpcNatCost';

describe('lambda-vpc-nat-cost', () => {
  const run = (template: CfnTemplate) => runRules(template, [lambdaVpcNatCost]);

  const vpcFn = {
    Type: 'AWS::Lambda::Function',
    Properties: { VpcConfig: { SubnetIds: ['subnet-1'] } },
  };
  const nat = {
    Type: 'AWS::EC2::NatGateway',
    Properties: { SubnetId: 'subnet-1' },
  };

  it('flags a VPC-attached function when a NAT gateway is present', () => {
    expect(run({ Resources: { Fn: vpcFn, Nat: nat } })).toHaveLength(1);
  });

  it('does not flag without a NAT gateway, or for non-VPC functions', () => {
    expect(run({ Resources: { Fn: vpcFn } })).toHaveLength(0);
    expect(
      run({
        Resources: {
          Fn: { Type: 'AWS::Lambda::Function', Properties: {} },
          Nat: nat,
        },
      })
    ).toHaveLength(0);
  });
});
