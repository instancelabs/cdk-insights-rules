import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { mskDataVolumeCmkMissing } from './mskDataVolumeCmkMissing';

describe('msk-data-volume-cmk-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [mskDataVolumeCmkMissing]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::MSK::Cluster', Properties: { ...properties } },
    },
  });

  it('flags a cluster without a CMK on broker volumes', () => {
    expect(run(res({}))).toHaveLength(1);
    expect(run(res({ EncryptionInfo: {} }))).toHaveLength(1);
  });

  it('does not flag a customer-managed key (literal or intrinsic)', () => {
    expect(
      run(
        res({
          EncryptionInfo: {
            EncryptionAtRest: { DataVolumeKMSKeyId: 'arn:key' },
          },
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        res({
          EncryptionInfo: {
            EncryptionAtRest: { DataVolumeKMSKeyId: { Ref: 'Key' } },
          },
        })
      )
    ).toHaveLength(0);
  });
});
