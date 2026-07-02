import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { glueJobEncryptionMissing } from './glueJobEncryptionMissing';

describe('glue-job-encryption-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [glueJobEncryptionMissing]);

  const job = (properties: object): CfnTemplate => ({
    Resources: {
      Job: {
        Type: 'AWS::Glue::Job',
        Properties: { Role: 'arn:role', Command: {}, ...properties },
      },
    },
  });

  it('flags a job without a security configuration', () => {
    expect(run(job({}))).toHaveLength(1);
  });

  it('does not flag a job with a security configuration', () => {
    expect(run(job({ SecurityConfiguration: 'sec-config' }))).toHaveLength(0);
  });
});
