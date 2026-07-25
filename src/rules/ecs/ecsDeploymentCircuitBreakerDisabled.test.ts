import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecsDeploymentCircuitBreakerDisabled } from './ecsDeploymentCircuitBreakerDisabled';

describe('ecs-deployment-circuit-breaker-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecsDeploymentCircuitBreakerDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::ECS::Service', Properties: { ...properties } },
    },
  });

  it('flags an ECS-controller service without the circuit breaker', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('does not flag enabled circuit breakers or CODE_DEPLOY services', () => {
    expect(
      run(
        res({
          DeploymentConfiguration: {
            DeploymentCircuitBreaker: { Enable: true, Rollback: true },
          },
        })
      )
    ).toHaveLength(0);
    expect(
      run(res({ DeploymentController: { Type: 'CODE_DEPLOY' } }))
    ).toHaveLength(0);
  });

  it('accepts the CloudFormation string form "true"', () => {
    expect(
      run(
        res({
          DeploymentConfiguration: {
            DeploymentCircuitBreaker: { Enable: 'true', Rollback: 'true' },
          },
        })
      )
    ).toHaveLength(0);
  });

  it('skips intrinsic circuit-breaker values instead of flagging them', () => {
    expect(
      run(
        res({
          DeploymentConfiguration: {
            DeploymentCircuitBreaker: {
              Enable: { 'Fn::If': ['IsProd', true, false] },
            },
          },
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        res({
          DeploymentConfiguration: {
            DeploymentCircuitBreaker: { Ref: 'BreakerParam' },
          },
        })
      )
    ).toHaveLength(0);
  });

  it('skips an intrinsic DeploymentConfiguration container', () => {
    expect(
      run(
        res({
          DeploymentConfiguration: {
            'Fn::If': [
              'IsProd',
              { DeploymentCircuitBreaker: { Enable: true, Rollback: true } },
              { Ref: 'AWS::NoValue' },
            ],
          },
        })
      )
    ).toHaveLength(0);
  });
});
