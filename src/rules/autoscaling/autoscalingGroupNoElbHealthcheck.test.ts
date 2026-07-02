import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { autoscalingGroupNoElbHealthcheck } from './autoscalingGroupNoElbHealthcheck';

describe('autoscaling-group-no-elb-healthcheck', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [autoscalingGroupNoElbHealthcheck]);

  const asg = (properties: object): CfnTemplate => ({
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: { MinSize: '1', MaxSize: '3', ...properties },
      },
    },
  });

  it('flags an LB-attached group without ELB health checks', () => {
    expect(run(asg({ TargetGroupARNs: ['arn:tg'] }))).toHaveLength(1);
    expect(
      run(asg({ LoadBalancerNames: ['lb'], HealthCheckType: 'EC2' }))
    ).toHaveLength(1);
  });

  it('does not flag ELB health checks or unattached groups', () => {
    expect(
      run(asg({ TargetGroupARNs: ['arn:tg'], HealthCheckType: 'ELB' }))
    ).toHaveLength(0);
    expect(run(asg({}))).toHaveLength(0);
  });
});
