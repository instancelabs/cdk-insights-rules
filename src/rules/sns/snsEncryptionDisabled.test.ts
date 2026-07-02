import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { snsEncryptionDisabled } from './snsEncryptionDisabled';

describe('sns-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [snsEncryptionDisabled]);

  it('flags a topic without a KMS key', () => {
    expect(
      run({
        Resources: { Topic: { Type: 'AWS::SNS::Topic', Properties: {} } },
      })
    ).toHaveLength(1);
  });

  it('does not flag a topic with a KMS key (literal or intrinsic)', () => {
    expect(
      run({
        Resources: {
          Aws: {
            Type: 'AWS::SNS::Topic',
            Properties: { KmsMasterKeyId: 'alias/aws/sns' },
          },
          Cmk: {
            Type: 'AWS::SNS::Topic',
            Properties: { KmsMasterKeyId: { Ref: 'Key' } },
          },
        },
      })
    ).toHaveLength(0);
  });
});
