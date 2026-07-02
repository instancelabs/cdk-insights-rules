import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { elbDeletionProtectionDisabled } from './elbDeletionProtectionDisabled';

describe('elb-deletion-protection-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [elbDeletionProtectionDisabled]);

  const alb = (attributes?: object[]): CfnTemplate => ({
    Resources: {
      Alb: {
        Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
        Properties: attributes ? { LoadBalancerAttributes: attributes } : {},
      },
    },
  });

  it('flags a load balancer without deletion protection', () => {
    expect(run(alb())).toHaveLength(1);
    expect(
      run(alb([{ Key: 'deletion_protection.enabled', Value: 'false' }]))
    ).toHaveLength(1);
  });

  it('does not flag enabled deletion protection', () => {
    expect(
      run(alb([{ Key: 'deletion_protection.enabled', Value: 'true' }]))
    ).toHaveLength(0);
  });
});
