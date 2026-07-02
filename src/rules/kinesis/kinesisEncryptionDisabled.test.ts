import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { kinesisEncryptionDisabled } from './kinesisEncryptionDisabled';

const stream = (properties: object): CfnTemplate => ({
  Resources: {
    Stream: { Type: 'AWS::Kinesis::Stream', Properties: properties },
  },
});

describe('kinesis-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [kinesisEncryptionDisabled]);

  it('flags a stream with no StreamEncryption or EncryptionType NONE', () => {
    expect(run(stream({ ShardCount: 1 }))).toHaveLength(1);
    expect(
      run(stream({ StreamEncryption: { EncryptionType: 'NONE' } }))
    ).toHaveLength(1);
  });

  it('does not flag KMS-encrypted streams or intrinsic values', () => {
    expect(
      run(
        stream({
          StreamEncryption: {
            EncryptionType: 'KMS',
            KeyId: 'alias/aws/kinesis',
          },
        })
      )
    ).toHaveLength(0);
    expect(
      run(stream({ StreamEncryption: { Ref: 'EncryptionSetting' } }))
    ).toHaveLength(0);
  });
});
