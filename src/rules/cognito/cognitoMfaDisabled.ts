import type { Rule } from '../../types';

/**
 * cognito-mfa-disabled
 *
 * A user pool with MfaConfiguration OFF (or unset — OFF is the default)
 * leaves accounts protected by passwords alone.
 */
export const cognitoMfaDisabled: Rule = {
  metadata: {
    ruleId: 'cognito-mfa-disabled',
    name: 'Cognito MFA Disabled',
    description:
      'Detects Cognito user pools with multi-factor authentication disabled.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Cognito::UserPool'],
    awsDocUrl:
      'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html',
    remediationSteps: [
      'Set MfaConfiguration to ON (or OPTIONAL as a migration step) with software-token MFA enabled',
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
      const mfa = resource.Properties?.MfaConfiguration;
      if (!mfa || mfa === 'OFF') {
        report(resourceId, {
          issue: 'Cognito user pool has MFA disabled.',
          recommendation:
            'Set MfaConfiguration to ON (or OPTIONAL during rollout) so accounts are not protected by passwords alone.',
        });
      }
    }
  },

  example: {
    flagged: `import * as cognito from 'aws-cdk-lib/aws-cognito';

new cognito.CfnUserPool(this, 'UserPool', {});`,
    fixed: `import * as cognito from 'aws-cdk-lib/aws-cognito';

new cognito.CfnUserPool(this, 'UserPool', {
  mfaConfiguration: 'ON',
  enabledMfas: ['SOFTWARE_TOKEN_MFA'],
});`,
  },
};
