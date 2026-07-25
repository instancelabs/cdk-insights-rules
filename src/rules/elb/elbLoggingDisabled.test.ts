import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { elbLoggingDisabled } from './elbLoggingDisabled';

describe('elb-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [elbLoggingDisabled]);

  const alb = (properties: object): CfnTemplate => ({
    Resources: {
      Alb: {
        Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
        Properties: properties,
      },
    },
  });

  it('flags a load balancer without access logging', () => {
    expect(run(alb({}))).toHaveLength(1);
    expect(
      run(
        alb({
          LoadBalancerAttributes: [
            { Key: 'access_logs.s3.enabled', Value: 'false' },
          ],
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag enabled access logging', () => {
    expect(
      run(
        alb({
          LoadBalancerAttributes: [
            { Key: 'access_logs.s3.enabled', Value: 'true' },
            { Key: 'access_logs.s3.bucket', Value: 'logs' },
          ],
        })
      )
    ).toHaveLength(0);
  });

  it('skips intrinsic attribute lists, entries, and values', () => {
    expect(
      run(alb({ LoadBalancerAttributes: { Ref: 'AttrsParam' } }))
    ).toHaveLength(0);
    expect(
      run(
        alb({
          LoadBalancerAttributes: [
            {
              'Fn::If': [
                'LogsOn',
                { Key: 'access_logs.s3.enabled', Value: 'true' },
                { Ref: 'AWS::NoValue' },
              ],
            },
          ],
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        alb({
          LoadBalancerAttributes: [
            {
              Key: 'access_logs.s3.enabled',
              Value: { 'Fn::If': ['LogsOn', 'true', 'false'] },
            },
          ],
        })
      )
    ).toHaveLength(0);
  });
});
