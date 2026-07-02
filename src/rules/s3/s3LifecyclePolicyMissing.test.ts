import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3LifecyclePolicyMissing } from './s3LifecyclePolicyMissing';

describe('s3-lifecycle-policy-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3LifecyclePolicyMissing]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::S3::Bucket', Properties: { ...properties } },
    },
  });

  it('flags a bucket with no lifecycle rules', () => {
    expect(run(res({}))).toHaveLength(1);
    expect(run(res({ LifecycleConfiguration: { Rules: [] } }))).toHaveLength(1);
  });

  it('does not flag configured lifecycle rules', () => {
    expect(
      run(
        res({
          LifecycleConfiguration: {
            Rules: [{ Id: 'x', Status: 'Enabled' }],
          },
        })
      )
    ).toHaveLength(0);
  });
});
