import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { redshiftAuditLoggingDisabled } from './redshiftAuditLoggingDisabled';

describe('redshift-audit-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [redshiftAuditLoggingDisabled]);

  const cluster = (properties: object): CfnTemplate => ({
    Resources: {
      Cluster: { Type: 'AWS::Redshift::Cluster', Properties: properties },
    },
  });

  it('flags a cluster without logging', () => {
    expect(run(cluster({}))).toHaveLength(1);
  });

  it('does not flag S3 or CloudWatch logging', () => {
    expect(
      run(cluster({ LoggingProperties: { BucketName: 'logs' } }))
    ).toHaveLength(0);
    expect(
      run(
        cluster({
          LoggingProperties: {
            LogDestinationType: 'cloudwatch',
            LogExports: ['connectionlog'],
          },
        })
      )
    ).toHaveLength(0);
  });
});
