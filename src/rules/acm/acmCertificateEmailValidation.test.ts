import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { acmCertificateEmailValidation } from './acmCertificateEmailValidation';

describe('acm-certificate-email-validation', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [acmCertificateEmailValidation]);

  const cert = (properties: object): CfnTemplate => ({
    Resources: {
      Cert: {
        Type: 'AWS::CertificateManager::Certificate',
        Properties: { DomainName: 'example.com', ...properties },
      },
    },
  });

  it('flags email validation and disabled transparency logging', () => {
    expect(run(cert({ ValidationMethod: 'EMAIL' }))).toHaveLength(1);
    expect(
      run(
        cert({
          ValidationMethod: 'DNS',
          CertificateTransparencyLoggingPreference: 'DISABLED',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag DNS validation with transparency logging', () => {
    expect(run(cert({ ValidationMethod: 'DNS' }))).toHaveLength(0);
  });
});
