import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaReservedConcurrencyMissing } from './lambdaReservedConcurrencyMissing';

describe('lambda-reserved-concurrency-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaReservedConcurrencyMissing]);

  it('flags a function without reserved concurrency', () => {
    expect(
      run({
        Resources: {
          Fn: { Type: 'AWS::Lambda::Function', Properties: {} },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag configured concurrency or CDK-internal functions', () => {
    expect(
      run({
        Resources: {
          Fn: {
            Type: 'AWS::Lambda::Function',
            Properties: { ReservedConcurrentExecutions: 10 },
          },
          LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a: {
            Type: 'AWS::Lambda::Function',
            Properties: {},
          },
        },
      })
    ).toHaveLength(0);
  });
});
