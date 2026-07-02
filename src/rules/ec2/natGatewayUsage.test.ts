import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { natGatewayUsage } from './natGatewayUsage';

describe('nat-gateway-usage', () => {
  const run = (template: CfnTemplate) => runRules(template, [natGatewayUsage]);

  it('flags each NAT gateway as a cost decision', () => {
    expect(
      run({
        Resources: {
          NatA: { Type: 'AWS::EC2::NatGateway', Properties: {} },
          NatB: { Type: 'AWS::EC2::NatGateway', Properties: {} },
        },
      })
    ).toHaveLength(2);
  });

  it('does not flag other resources', () => {
    expect(
      run({
        Resources: {
          Vpc: { Type: 'AWS::EC2::VPC', Properties: {} },
        },
      })
    ).toHaveLength(0);
  });
});
