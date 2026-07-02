import type { Rule } from '../../types';

/**
 * cognito-advanced-security-disabled
 *
 * Advanced security (threat protection) detects compromised credentials and
 * risky sign-ins. Advisory: it requires the Cognito Plus feature plan, so
 * this stays LOW.
 */
export const cognitoAdvancedSecurityDisabled: Rule = {
  metadata: {
    ruleId: 'cognito-advanced-security-disabled',
    name: 'Cognito Advanced Security Disabled',
    description:
      'Detects Cognito user pools without advanced security features (compromised-credential detection).',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Cognito::UserPool'],
    awsDocUrl:
      'https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-advanced-security.html',
    remediationSteps: [
      'Set UserPoolAddOns.AdvancedSecurityMode to AUDIT or ENFORCED (requires the Plus feature plan)',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Cognito::UserPool') {
        continue;
      }
      const mode = resource.Properties?.UserPoolAddOns?.AdvancedSecurityMode;
      if (!mode || mode === 'OFF') {
        report(resourceId, {
          issue:
            'Cognito user pool does not have advanced security features enabled.',
          recommendation:
            'Set UserPoolAddOns.AdvancedSecurityMode to AUDIT or ENFORCED to detect compromised credentials and block suspicious sign-ins.',
        });
      }
    }
  },

  example: {
    flagged: `import * as cognito from 'aws-cdk-lib/aws-cognito';

new cognito.CfnUserPool(this, 'UserPool', {
  mfaConfiguration: 'ON',
  enabledMfas: ['SOFTWARE_TOKEN_MFA'],
});`,
    fixed: `import * as cognito from 'aws-cdk-lib/aws-cognito';

new cognito.CfnUserPool(this, 'UserPool', {
  mfaConfiguration: 'ON',
  enabledMfas: ['SOFTWARE_TOKEN_MFA'],
  userPoolAddOns: {
    advancedSecurityMode: 'ENFORCED',
  },
});`,
  },
};
