import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ebsVolumeGp2Storage } from './ebsVolumeGp2Storage';

describe('ebs-volume-gp2-storage', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ebsVolumeGp2Storage]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: {
        Type: 'AWS::EC2::Volume',
        Properties: { AvailabilityZone: 'eu-west-2a', ...properties },
      },
    },
  });

  it('flags gp2 volumes', () => {
    expect(run(res({ VolumeType: 'gp2' }))).toHaveLength(1);
  });

  it('does not flag gp3, io2, defaults, or intrinsics', () => {
    expect(run(res({ VolumeType: 'gp3' }))).toHaveLength(0);
    expect(run(res({ VolumeType: 'io2' }))).toHaveLength(0);
    expect(run(res({}))).toHaveLength(0);
    expect(run(res({ VolumeType: { Ref: 'TypeParam' } }))).toHaveLength(0);
  });
});
