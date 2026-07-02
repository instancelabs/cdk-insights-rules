import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3BucketVersioningDisabled } from './s3BucketVersioningDisabled';

describe('s3-bucket-versioning-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3BucketVersioningDisabled]).map(
      (finding) => finding.ruleId
    );

  it('flags a bucket with no versioning configuration', () => {
    expect(
      run({
        Resources: {
          Bucket: { Type: 'AWS::S3::Bucket', Properties: {} },
        },
      })
    ).toContain('s3-bucket-versioning-disabled');
  });

  it('flags a bucket with versioning Suspended', () => {
    expect(
      run({
        Resources: {
          Bucket: {
            Type: 'AWS::S3::Bucket',
            Properties: { VersioningConfiguration: { Status: 'Suspended' } },
          },
        },
      })
    ).toContain('s3-bucket-versioning-disabled');
  });

  it('does not flag a Status set via an intrinsic (undecidable)', () => {
    expect(
      run({
        Resources: {
          Bucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              VersioningConfiguration: {
                Status: { 'Fn::If': ['IsProd', 'Enabled', 'Suspended'] },
              },
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag a bucket with versioning Enabled', () => {
    expect(
      run({
        Resources: {
          Bucket: {
            Type: 'AWS::S3::Bucket',
            Properties: { VersioningConfiguration: { Status: 'Enabled' } },
          },
        },
      })
    ).toHaveLength(0);
  });
});
