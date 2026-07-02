import { asStatements, isPublicStatement } from '../../policy.js';
import type { Rule } from '../../types';

/**
 * kms-key-policy-public
 *
 * A KMS key policy statement that Allows a wildcard principal without a
 * scoping Condition (aws:PrincipalAccount, kms:CallerAccount, org/source
 * conditions, ...) grants the world access to the key. Deny statements and
 * account-scoped wildcard grants are fine and never flagged.
 */
export const kmsKeyPolicyPublic: Rule = {
  metadata: {
    ruleId: 'kms-key-policy-public',
    name: 'KMS Key Policy Allows Public Access',
    description:
      'Detects KMS keys whose key policy grants access to a wildcard or public principal without a scoping condition.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::KMS::Key'],
    awsDocUrl:
      'https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html',
    remediationSteps: [
      'Remove wildcard/public principals from the key policy',
      'Scope key access to specific IAM principals or accounts (e.g. the account root ARN), or add a Condition such as kms:CallerAccount',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::KMS::Key') {
        continue;
      }
      const statements = asStatements(resource.Properties?.KeyPolicy);
      if (statements.some(isPublicStatement)) {
        report(resourceId, {
          issue:
            'KMS key policy grants access to a wildcard principal with no scoping condition, making the key publicly usable.',
          recommendation:
            'Restrict the key policy to specific IAM roles, users, or accounts — or scope the wildcard with a Condition like kms:CallerAccount or aws:PrincipalOrgID.',
        });
      }
    }
  },

  example: {
    flagged: `import * as kms from 'aws-cdk-lib/aws-kms';

new kms.CfnKey(this, 'Key', {
  keyPolicy: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: '*',
        Action: 'kms:*',
        Resource: '*',
      },
    ],
  },
});`,
    fixed: `import * as kms from 'aws-cdk-lib/aws-kms';

new kms.CfnKey(this, 'Key', {
  keyPolicy: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        Action: 'kms:*',
        Resource: '*',
      },
    ],
  },
});`,
  },
};
