import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecrLifecyclePolicyMissing } from './ecrLifecyclePolicyMissing';

describe('ecr-lifecycle-policy-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecrLifecyclePolicyMissing]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::ECR::Repository', Properties: { ...properties } },
    },
  });

  it('flags a repository without a lifecycle policy', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('does not flag a lifecycle policy', () => {
    expect(
      run(res({ LifecyclePolicy: { LifecyclePolicyText: '{"rules":[]}' } }))
    ).toHaveLength(0);
  });
});
