import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudwatchLogsEncryptionDisabled } from './cloudwatchLogsEncryptionDisabled';

describe('cloudwatch-logs-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudwatchLogsEncryptionDisabled]);

  it('flags a log group without a KMS key', () => {
    expect(
      run({
        Resources: {
          Lg: { Type: 'AWS::Logs::LogGroup', Properties: {} },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag a log group with a KMS key (literal or intrinsic)', () => {
    expect(
      run({
        Resources: {
          Literal: {
            Type: 'AWS::Logs::LogGroup',
            Properties: { KmsKeyId: 'arn:key' },
          },
          Intrinsic: {
            Type: 'AWS::Logs::LogGroup',
            Properties: { KmsKeyId: { 'Fn::GetAtt': ['Key', 'Arn'] } },
          },
        },
      })
    ).toHaveLength(0);
  });
});
