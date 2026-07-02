import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eksSecretsEncryptionDisabled } from './eksSecretsEncryptionDisabled';

const cluster = (properties: object): CfnTemplate => ({
  Resources: {
    Cluster: { Type: 'AWS::EKS::Cluster', Properties: properties },
  },
});

describe('eks-secrets-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eksSecretsEncryptionDisabled]);

  it('flags a cluster with no secrets encryption config', () => {
    expect(run(cluster({}))).toHaveLength(1);
    expect(
      run(cluster({ EncryptionConfig: [{ Resources: ['other'] }] }))
    ).toHaveLength(1);
  });

  it('does not flag a cluster encrypting secrets', () => {
    expect(
      run(
        cluster({
          EncryptionConfig: [
            { Resources: ['secrets'], Provider: { KeyArn: 'arn:...' } },
          ],
        })
      )
    ).toHaveLength(0);
  });
});
