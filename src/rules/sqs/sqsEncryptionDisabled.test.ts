import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { sqsEncryptionDisabled } from './sqsEncryptionDisabled';

const queue = (properties: object): CfnTemplate => ({
  Resources: {
    Queue: { Type: 'AWS::SQS::Queue', Properties: properties },
  },
});

describe('sqs-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [sqsEncryptionDisabled]);

  it('flags a queue that explicitly disables SSE', () => {
    expect(run(queue({ SqsManagedSseEnabled: false }))).toHaveLength(1);
    expect(run(queue({ SqsManagedSseEnabled: 'false' }))).toHaveLength(1);
  });

  it('does not flag the default (SSE-SQS applies to new queues)', () => {
    expect(run(queue({}))).toHaveLength(0);
  });

  it('does not flag KMS- or SSE-SQS-encrypted queues', () => {
    expect(run(queue({ KmsMasterKeyId: 'alias/aws/sqs' }))).toHaveLength(0);
    expect(run(queue({ SqsManagedSseEnabled: true }))).toHaveLength(0);
    expect(
      run(
        queue({ SqsManagedSseEnabled: false, KmsMasterKeyId: { Ref: 'Key' } })
      )
    ).toHaveLength(0);
  });
});
