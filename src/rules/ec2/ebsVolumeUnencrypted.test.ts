import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ebsVolumeUnencrypted } from './ebsVolumeUnencrypted';

describe('ebs-volume-unencrypted', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ebsVolumeUnencrypted]);

  it('flags an unencrypted volume (absent or false)', () => {
    expect(
      run({
        Resources: {
          Absent: {
            Type: 'AWS::EC2::Volume',
            Properties: { AvailabilityZone: 'eu-west-2a', Size: 10 },
          },
          Explicit: {
            Type: 'AWS::EC2::Volume',
            Properties: {
              AvailabilityZone: 'eu-west-2a',
              Size: 10,
              Encrypted: false,
            },
          },
        },
      })
    ).toHaveLength(2);
  });

  it('does not flag an encrypted volume (boolean or string form)', () => {
    expect(
      run({
        Resources: {
          Vol: {
            Type: 'AWS::EC2::Volume',
            Properties: {
              AvailabilityZone: 'eu-west-2a',
              Size: 10,
              Encrypted: 'true',
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag Encrypted set via an intrinsic (undecidable)', () => {
    expect(
      run({
        Resources: {
          Vol: {
            Type: 'AWS::EC2::Volume',
            Properties: {
              AvailabilityZone: 'eu-west-2a',
              Size: 10,
              Encrypted: { 'Fn::If': ['Prod', true, false] },
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
