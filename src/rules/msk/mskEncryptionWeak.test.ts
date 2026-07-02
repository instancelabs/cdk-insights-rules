import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { mskEncryptionWeak } from './mskEncryptionWeak';

const cluster = (encryptionInfo?: object): CfnTemplate => ({
  Resources: {
    Cluster: {
      Type: 'AWS::MSK::Cluster',
      Properties: encryptionInfo ? { EncryptionInfo: encryptionInfo } : {},
    },
  },
});

describe('msk-encryption-weak', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [mskEncryptionWeak]);

  it('flags plaintext client-broker settings', () => {
    expect(
      run(cluster({ EncryptionInTransit: { ClientBroker: 'PLAINTEXT' } }))
    ).toHaveLength(1);
    expect(
      run(cluster({ EncryptionInTransit: { ClientBroker: 'TLS_PLAINTEXT' } }))
    ).toHaveLength(1);
  });

  it('flags disabled inter-broker encryption', () => {
    expect(
      run(cluster({ EncryptionInTransit: { InCluster: false } }))
    ).toHaveLength(1);
  });

  it('does not flag TLS defaults', () => {
    expect(run(cluster())).toHaveLength(0);
    expect(
      run(
        cluster({
          EncryptionInTransit: { ClientBroker: 'TLS', InCluster: true },
        })
      )
    ).toHaveLength(0);
  });
});
