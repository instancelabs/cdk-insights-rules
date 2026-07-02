import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ec2InstanceTypeOutdated } from './ec2InstanceTypeOutdated';

describe('ec2-instance-type-outdated', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ec2InstanceTypeOutdated]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::EC2::Instance', Properties: { ...properties } },
    },
  });

  it('flags t2 instances', () => {
    expect(run(res({ InstanceType: 't2.large' }))).toHaveLength(1);
  });

  it('does not flag t3 or intrinsic types', () => {
    expect(run(res({ InstanceType: 't3.large' }))).toHaveLength(0);
    expect(run(res({ InstanceType: { Ref: 'TypeParam' } }))).toHaveLength(0);
  });
});
