import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecrMutableTags } from './ecrMutableTags';

describe('ecr-mutable-tags', () => {
  const run = (template: CfnTemplate) => runRules(template, [ecrMutableTags]);

  const repo = (properties: object): CfnTemplate => ({
    Resources: {
      Repo: { Type: 'AWS::ECR::Repository', Properties: properties },
    },
  });

  it('flags mutable tags (absent or explicit MUTABLE)', () => {
    expect(run(repo({}))).toHaveLength(1);
    expect(run(repo({ ImageTagMutability: 'MUTABLE' }))).toHaveLength(1);
  });

  it('does not flag immutable settings or intrinsics', () => {
    expect(run(repo({ ImageTagMutability: 'IMMUTABLE' }))).toHaveLength(0);
    expect(
      run(repo({ ImageTagMutability: 'IMMUTABLE_WITH_EXCLUSION' }))
    ).toHaveLength(0);
    expect(
      run(repo({ ImageTagMutability: { Ref: 'MutabilityParam' } }))
    ).toHaveLength(0);
  });
});
