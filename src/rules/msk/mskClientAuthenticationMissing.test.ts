import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { mskClientAuthenticationMissing } from './mskClientAuthenticationMissing';

const cluster = (auth?: object): CfnTemplate => ({
  Resources: {
    Cluster: {
      Type: 'AWS::MSK::Cluster',
      Properties: auth ? { ClientAuthentication: auth } : {},
    },
  },
});

describe('msk-client-authentication-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [mskClientAuthenticationMissing]);

  it('flags a cluster with no client authentication', () => {
    expect(run(cluster())).toHaveLength(1);
  });

  it('flags explicitly enabled unauthenticated access', () => {
    const findings = run(
      cluster({
        Sasl: { Iam: { Enabled: true } },
        Unauthenticated: { Enabled: true },
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('unauthenticated');
  });

  it('does not flag IAM, SCRAM, or mutual-TLS auth', () => {
    expect(run(cluster({ Sasl: { Iam: { Enabled: true } } }))).toHaveLength(0);
    expect(run(cluster({ Sasl: { Scram: { Enabled: true } } }))).toHaveLength(
      0
    );
    expect(
      run(cluster({ Tls: { CertificateAuthorityArnList: ['arn:...'] } }))
    ).toHaveLength(0);
  });
});
