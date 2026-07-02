import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaRuntimeDeprecated } from './lambdaRuntimeDeprecated';

const fn = (runtime?: unknown): CfnTemplate => ({
  Resources: {
    Fn: {
      Type: 'AWS::Lambda::Function',
      Properties: runtime === undefined ? {} : { Runtime: runtime },
    },
  },
});

describe('lambda-runtime-deprecated', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaRuntimeDeprecated]);

  it('flags deprecated runtimes and names the replacement', () => {
    const findings = run(fn('nodejs14.x'));
    expect(findings).toHaveLength(1);
    expect(findings[0].recommendation).toContain('nodejs22.x');
    expect(run(fn('python3.8'))).toHaveLength(1);
    expect(run(fn('go1.x'))).toHaveLength(1);
  });

  it('does not flag current runtimes or container images (no Runtime)', () => {
    expect(run(fn('nodejs22.x'))).toHaveLength(0);
    expect(run(fn('python3.13'))).toHaveLength(0);
    expect(run(fn())).toHaveLength(0);
  });
});
