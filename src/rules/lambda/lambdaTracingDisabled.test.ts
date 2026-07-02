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

  it('does not flag CDK-internal helper functions the user cannot configure', () => {
    expect(
      run({
        Resources: {
          LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a: {
            Type: 'AWS::Lambda::Function',
            Properties: {},
          },
          CustomS3AutoDeleteObjectsCustomResourceProviderHandler9D90184F: {
            Type: 'AWS::Lambda::Function',
            Properties: {},
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag Mode set via an intrinsic (undecidable)', () => {
    expect(
      run({
        Resources: {
          Fn: {
            Type: 'AWS::Lambda::Function',
            Properties: {
              TracingConfig: {
                Mode: { 'Fn::If': ['Trace', 'Active', 'PassThrough'] },
              },
            },
          },
        },
      })
    ).toHaveLength(0);
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
