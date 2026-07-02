import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudfrontTlsOutdated } from './cloudfrontTlsOutdated';

describe('cloudfront-tls-outdated', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudfrontTlsOutdated]);

  const distribution = (viewerCertificate?: object): CfnTemplate => ({
    Resources: {
      Dist: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: viewerCertificate
            ? { ViewerCertificate: viewerCertificate }
            : {},
        },
      },
    },
  });

  it('flags outdated versions and the implicit TLSv1 default with a custom cert', () => {
    expect(
      run(
        distribution({
          AcmCertificateArn: 'arn:cert',
          MinimumProtocolVersion: 'TLSv1',
        })
      )
    ).toHaveLength(1);
    expect(run(distribution({ AcmCertificateArn: 'arn:cert' }))).toHaveLength(
      1
    );
  });

  it('does not flag modern versions or the default CloudFront certificate', () => {
    expect(
      run(
        distribution({
          AcmCertificateArn: 'arn:cert',
          MinimumProtocolVersion: 'TLSv1.2_2021',
        })
      )
    ).toHaveLength(0);
    expect(
      run(distribution({ CloudFrontDefaultCertificate: true }))
    ).toHaveLength(0);
    expect(run(distribution())).toHaveLength(0);
  });
});
