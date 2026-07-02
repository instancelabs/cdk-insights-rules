import { asStatements, findSelfLockoutAction } from '../../policy.js';
import type { Rule } from '../../types';

const LOCKOUT_ACTIONS = new Set(['*', 'kms:*', 'kms:PutKeyPolicy']);

/**
 * kms-key-policy-self-lockout
 *
 * A key policy that Denies `kms:*` or `kms:PutKeyPolicy` to `Principal: '*'`
 * with no root/admin carveout makes the key unmanageable: nobody can edit the
 * policy to undo the Deny. KMS lockouts are the worst of the family — AWS
 * cannot restore access to an unmanageable key.
 */
export const kmsKeyPolicySelfLockout: Rule = {
  metadata: {
    ruleId: 'kms-key-policy-self-lockout',
    name: 'KMS Key Policy Self-Lockout',
    description:
      'Detects KMS key policies whose blanket Deny statements would make the key unmanageable.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::KMS::Key'],
    awsDocUrl:
      'https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html',
    remediationSteps: [
      'Exempt the account root or admin role(s) from the Deny via a Condition (e.g. ArnNotLike on aws:PrincipalArn)',
      'Keep the standard root-account Allow statement in every key policy so the key stays manageable',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::KMS::Key') {
        continue;
      }
      const statements = asStatements(resource.Properties?.KeyPolicy);
      const matched = statements
        .map((statement) => findSelfLockoutAction(statement, LOCKOUT_ACTIONS))
        .find((action) => action !== undefined);
      if (matched) {
        report(resourceId, {
          issue: `KMS key policy Denies ${matched} to Principal '*' with no carveout for the account root or an admin role, making the key unmanageable.`,
          recommendation:
            'Exempt your admin role(s) or the account root via a Condition — a fully locked key policy cannot be repaired, even by AWS.',
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
        Effect: 'Deny',
        Principal: '*',
        Action: 'kms:PutKeyPolicy',
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
        Effect: 'Deny',
        Principal: '*',
        Action: 'kms:PutKeyPolicy',
        Resource: '*',
        Condition: {
          ArnNotLike: {
            'aws:PrincipalArn': 'arn:aws:iam::111122223333:role/Admin',
          },
        },
      },
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
