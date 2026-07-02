import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudfrontLoggingDisabled } from './cloudfrontLoggingDisabled';

describe('cloudfront-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudfrontLoggingDisabled]);

  const dist = (config: object): CfnTemplate => ({
    Resources: {
      Dist: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: { DistributionConfig: config },
      },
    },
  });

  it('flags a distribution without logging', () => {
    expect(run(dist({}))).toHaveLength(1);
  });

  it('does not flag logging with a bucket (literal or intrinsic)', () => {
    expect(
      run(dist({ Logging: { Bucket: 'logs.s3.amazonaws.com' } }))
    ).toHaveLength(0);
    expect(
      run(dist({ Logging: { Bucket: { 'Fn::GetAtt': ['B', 'DomainName'] } } }))
    ).toHaveLength(0);
  });
});
