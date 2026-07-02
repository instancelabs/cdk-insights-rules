import type { Rule } from '../../types';

/**
 * acm-certificate-email-validation
 *
 * Email-validated certificates require a human to click a link on renewal —
 * a production outage waiting to happen. Also flags disabled certificate
 * transparency logging.
 */
export const acmCertificateEmailValidation: Rule = {
  metadata: {
    ruleId: 'acm-certificate-email-validation',
    name: 'ACM Certificate Email Validation',
    description:
      'Detects ACM certificates using email validation instead of DNS, or with certificate transparency logging disabled.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::CertificateManager::Certificate'],
    awsDocUrl:
      'https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html',
    remediationSteps: [
      'Set ValidationMethod to DNS so certificates renew automatically',
      'Leave CertificateTransparencyLoggingPreference enabled',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::CertificateManager::Certificate') {
        continue;
      }
      const props = resource.Properties ?? {};
      if (props.ValidationMethod !== 'DNS') {
        report(resourceId, {
          issue:
            'ACM certificate uses email validation instead of DNS validation.',
          recommendation:
            'Use DNS validation so renewals are automatic — email validation needs manual intervention and expires certificates when missed.',
        });
      }
      if (props.CertificateTransparencyLoggingPreference === 'DISABLED') {
        report(resourceId, {
          issue:
            'ACM certificate has certificate transparency logging disabled.',
          recommendation:
            'Enable certificate transparency logging so misissued certificates for your domains are detectable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';

new certificatemanager.CfnCertificate(this, 'Cert', {
  domainName: 'example.com',
  validationMethod: 'EMAIL',
});`,
    fixed: `import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';

new certificatemanager.CfnCertificate(this, 'Cert', {
  domainName: 'example.com',
  validationMethod: 'DNS',
});`,
  },
};
