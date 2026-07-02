import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudfrontHttpsOnly } from './cloudfrontHttpsOnly';

const distribution = (config: object): CfnTemplate => ({
  Resources: {
    Dist: {
      Type: 'AWS::CloudFront::Distribution',
      Properties: { DistributionConfig: config },
    },
  },
});

describe('cloudfront-https-only', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudfrontHttpsOnly]);

  it('flags allow-all on the default cache behavior', () => {
    expect(
      run(
        distribution({
          DefaultCacheBehavior: { ViewerProtocolPolicy: 'allow-all' },
        })
      )
    ).toHaveLength(1);
  });

  it('flags allow-all on an additional cache behavior', () => {
    expect(
      run(
        distribution({
          DefaultCacheBehavior: { ViewerProtocolPolicy: 'redirect-to-https' },
          CacheBehaviors: [{ ViewerProtocolPolicy: 'allow-all' }],
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag https-only or redirect-to-https behaviors', () => {
    expect(
      run(
        distribution({
          DefaultCacheBehavior: { ViewerProtocolPolicy: 'https-only' },
          CacheBehaviors: [{ ViewerProtocolPolicy: 'redirect-to-https' }],
        })
      )
    ).toHaveLength(0);
  });
});
