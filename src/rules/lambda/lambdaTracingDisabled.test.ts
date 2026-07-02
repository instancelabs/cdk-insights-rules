import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaTracingDisabled } from './lambdaTracingDisabled';

describe('lambda-tracing-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaTracingDisabled]).map(
      (finding) => finding.ruleId
    );

  it('flags a function with no TracingConfig', () => {
    expect(
      run({
        Resources: {
          Fn: { Type: 'AWS::Lambda::Function', Properties: {} },
        },
      })
    ).toContain('lambda-tracing-disabled');
  });

  it('flags a function with TracingConfig.Mode PassThrough', () => {
    expect(
      run({
        Resources: {
          Fn: {
            Type: 'AWS::Lambda::Function',
            Properties: { TracingConfig: { Mode: 'PassThrough' } },
          },
        },
      })
    ).toContain('lambda-tracing-disabled');
  });

  it('does not flag a function with TracingConfig.Mode Active', () => {
    expect(
      run({
        Resources: {
          Fn: {
            Type: 'AWS::Lambda::Function',
            Properties: { TracingConfig: { Mode: 'Active' } },
          },
        },
      })
    ).toHaveLength(0);
  });
});
