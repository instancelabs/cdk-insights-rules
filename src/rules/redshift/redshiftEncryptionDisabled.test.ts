import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { redshiftEncryptionDisabled } from './redshiftEncryptionDisabled';

const cluster = (properties: object): CfnTemplate => ({
  Resources: {
    Cluster: { Type: 'AWS::Redshift::Cluster', Properties: properties },
  },
});

describe('redshift-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [redshiftEncryptionDisabled]);

  it('flags an unencrypted cluster (absent or false)', () => {
    expect(run(cluster({}))).toHaveLength(1);
    expect(run(cluster({ Encrypted: false }))).toHaveLength(1);
  });

  it('does not flag an encrypted cluster or an intrinsic value', () => {
    expect(run(cluster({ Encrypted: true }))).toHaveLength(0);
    expect(run(cluster({ Encrypted: 'true' }))).toHaveLength(0);
    expect(
      run(cluster({ Encrypted: { 'Fn::If': ['X', true, false] } }))
    ).toHaveLength(0);
  });
});
