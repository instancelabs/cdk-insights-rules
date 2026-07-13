import { asStatements, isPublicStatement } from '../../policy.js';
import type { Rule } from '../../types';

/**
 * iam-role-anonymous-assume
 *
 * A trust policy that allows a wildcard principal to assume the role with no
 * scoping condition means ANY principal in ANY AWS account can become this
 * role — every permission attached to it is effectively public. This is more
 * severe than the cross-account case (which at least names an account).
 * Conditions like aws:PrincipalOrgID/SourceArn scope the grant and are not
 * flagged (see isPublicStatement).
 */
export const iamRoleAnonymousAssume: Rule = {
  metadata: {
    ruleId: 'iam-role-anonymous-assume',
    name: 'IAM Role Assumable By Any AWS Account',
    description:
      'Detects IAM roles whose trust policy allows a wildcard principal to assume them with no scoping condition — anyone with an AWS account can become the role.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::IAM::Role'],
    awsDocUrl:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_policy-examples.html',
    remediationSteps: [
      'Name the trusted principals explicitly (account root ARNs, service principals, or federated providers)',
      'If broad trust is intended, scope it with a Condition such as aws:PrincipalOrgID or an sts:ExternalId',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::IAM::Role') {
        continue;
      }
      const statements = asStatements(
        resource.Properties?.AssumeRolePolicyDocument
      );
      if (statements.some(isPublicStatement)) {
        report(resourceId, {
          issue:
            'IAM role trust policy allows a wildcard principal to assume the role with no scoping condition — any AWS account can assume it.',
          recommendation:
            'Restrict the trust policy to named principals, or scope a broad grant with aws:PrincipalOrgID / sts:ExternalId conditions.',
        });
      }
    }
  },

  example: {
    flagged: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnRole(this, 'SupportRole', {
  assumeRolePolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: 'sts:AssumeRole',
      },
    ],
  },
});`,
    fixed: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnRole(this, 'SupportRole', {
  assumeRolePolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        Action: 'sts:AssumeRole',
        Condition: { StringEquals: { 'sts:ExternalId': 'support-vendor' } },
      },
    ],
  },
});`,
  },
};
