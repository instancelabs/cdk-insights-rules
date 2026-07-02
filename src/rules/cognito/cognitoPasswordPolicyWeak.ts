import type { Rule } from '../../types';

/**
 * cognito-password-policy-weak
 *
 * Flags user pools with no password policy, or a minimum length below 12
 * characters. 12+ is the common benchmark (CIS, NIST-aligned guidance) for
 * resisting offline brute-force of leaked hashes.
 */
export const cognitoPasswordPolicyWeak: Rule = {
  metadata: {
    ruleId: 'cognito-password-policy-weak',
    name: 'Cognito Password Policy Weak',
    description:
      'Detects Cognito user pools with no password policy or a minimum length below 12 characters.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Cognito::UserPool'],
    awsDocUrl:
      'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html',
    remediationSteps: [
      'Configure Policies.PasswordPolicy with MinimumLength of at least 12 and all character-class requirements',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Cognito::UserPool') {
        continue;
      }
      const passwordPolicy = resource.Properties?.Policies?.PasswordPolicy;
      if (!passwordPolicy) {
        report(resourceId, {
          issue:
            'Cognito user pool has no password policy configured (defaults to an 8-character minimum).',
          recommendation:
            'Configure a password policy with MinimumLength of at least 12 plus uppercase, lowercase, number, and symbol requirements.',
        });
        continue;
      }
      const minimumLength = passwordPolicy.MinimumLength;
      if (typeof minimumLength === 'number' && minimumLength < 12) {
        report(resourceId, {
          issue: `Cognito password policy allows passwords as short as ${minimumLength} characters.`,
          recommendation:
            'Set MinimumLength to at least 12 characters to resist brute-force and credential-stuffing attacks.',
        });
      }
    }
  },

  example: {
    flagged: `import * as cognito from 'aws-cdk-lib/aws-cognito';

new cognito.CfnUserPool(this, 'UserPool', {
  policies: {
    passwordPolicy: { minimumLength: 8 },
  },
});`,
    fixed: `import * as cognito from 'aws-cdk-lib/aws-cognito';

new cognito.CfnUserPool(this, 'UserPool', {
  policies: {
    passwordPolicy: {
      minimumLength: 14,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSymbols: true,
    },
  },
});`,
  },
};
