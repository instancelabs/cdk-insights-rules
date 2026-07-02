import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaMemoryOptimization } from './lambdaMemoryOptimization';

describe('lambda-memory-optimization', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaMemoryOptimization]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::Lambda::Function', Properties: { ...properties } },
    },
  });

  it('flags memory above 1024 MB', () => {
    expect(run(res({ MemorySize: 3008 }))).toHaveLength(1);
  });

  it('does not flag 1024 MB or below, defaults, or intrinsics', () => {
    expect(run(res({ MemorySize: 1024 }))).toHaveLength(0);
    expect(run(res({}))).toHaveLength(0);
    expect(run(res({ MemorySize: { Ref: 'MemParam' } }))).toHaveLength(0);
  });
});
