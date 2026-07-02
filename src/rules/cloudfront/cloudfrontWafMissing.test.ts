import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudfrontWafMissing } from './cloudfrontWafMissing';

describe('cloudfront-waf-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudfrontWafMissing]);

  const dist = (config: object): CfnTemplate => ({
    Resources: {
      Dist: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: { DistributionConfig: config },
      },
    },
  });

  it('flags a distribution without a WebACL', () => {
    expect(run(dist({}))).toHaveLength(1);
  });

  it('does not flag a distribution with a WebACL (literal or intrinsic)', () => {
    expect(run(dist({ WebACLId: 'arn:acl' }))).toHaveLength(0);
    expect(
      run(dist({ WebACLId: { 'Fn::GetAtt': ['Acl', 'Arn'] } }))
    ).toHaveLength(0);
  });
});
