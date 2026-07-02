import { asStatements, isWildcardPrincipal } from '../../policy.js';
import type { Rule } from '../../types';

/**
 * True when a trust-policy principal includes an AWS account/user/role —
 * i.e. the role is assumable by people or foreign workloads, not only by an
 * AWS service.
 */
const hasAwsPrincipal = (principal: unknown): boolean => {
  if (typeof principal === 'string') {
    return (
      principal === '*' ||
      principal.startsWith('arn:') ||
      /^\d{12}$/.test(principal)
    );
  }
  if (principal && typeof principal === 'object') {
    return (principal as Record<string, unknown>).AWS !== undefined;
  }
  return false;
};

/**
 * iam-permission-boundary-missing
 *
 * Permission boundaries cap what a delegated role can ever do. Only roles
 * assumable by AWS principals (people, accounts, `*`) are flagged — pure
 * service roles (lambda.amazonaws.com etc.) are what every CDK construct
 * generates, and flagging them would bury the signal. (The product flags
 * every role; the open rule deliberately scopes to delegation roles.)
 */
export const iamPermissionBoundaryMissing: Rule = {
  metadata: {
    ruleId: 'iam-permission-boundary-missing',
    name: 'IAM Permission Boundary Missing',
    description:
      'Detects IAM roles assumable by AWS principals (users/accounts) without a permission boundary.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: ['AWS::IAM::Role'],
    awsDocUrl:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html',
    remediationSteps: [
      'Attach a PermissionsBoundary policy to roles assumed by people or other accounts',
    ],
    complianceFrameworks: ['SOC2', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::IAM::Role') {
        continue;
      }
      if (resource.Properties?.PermissionsBoundary) {
        continue;
      }
      const statements = asStatements(
        resource.Properties?.AssumeRolePolicyDocument
      );
      const assumableByAwsPrincipal = statements.some(
        (statement) =>
          statement.Effect === 'Allow' &&
          (hasAwsPrincipal(statement.Principal) ||
            isWildcardPrincipal(statement.Principal))
      );
      if (assumableByAwsPrincipal) {
        report(resourceId, {
          issue:
            'IAM role assumable by AWS principals has no permission boundary configured.',
          recommendation:
            'Attach a PermissionsBoundary to cap the maximum permissions of delegated access and prevent privilege escalation.',
        });
      }
    }
  },

  example: {
    flagged: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnRole(this, 'DeveloperRole', {
  assumeRolePolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        Action: 'sts:AssumeRole',
      },
    ],
  },
});`,
    fixed: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnRole(this, 'DeveloperRole', {
  assumeRolePolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        Action: 'sts:AssumeRole',
      },
    ],
  },
  permissionsBoundary:
    'arn:aws:iam::111122223333:policy/developer-boundary',
});`,
  },
};
