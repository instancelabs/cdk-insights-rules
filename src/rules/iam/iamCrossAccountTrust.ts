import { asStatements } from '../../policy.js';
import type { Rule } from '../../types';

const ACCOUNT_ID_PATTERN = /^\d{12}$/;
const ACCOUNT_ARN_PATTERN = /^arn:aws:(?:iam|sts)::(\d{12}):/;

const accountIdsFromPrincipal = (principal: unknown): string[] => {
  const fromString = (candidate: unknown): string[] => {
    if (typeof candidate !== 'string') {
      return [];
    }
    if (ACCOUNT_ID_PATTERN.test(candidate)) {
      return [candidate];
    }
    const match = candidate.match(ACCOUNT_ARN_PATTERN);
    return match ? [match[1]] : [];
  };
  if (typeof principal === 'string') {
    return fromString(principal);
  }
  if (principal && typeof principal === 'object') {
    const aws = (principal as Record<string, unknown>).AWS;
    const values = Array.isArray(aws) ? aws : [aws];
    return values.flatMap(fromString);
  }
  return [];
};

/**
 * iam-cross-account-trust
 *
 * A role trust policy naming a literal AWS account grants that whole account
 * assume rights. It cannot be decided from one template whether the account
 * is foreign, so this is a verify-it's-intentional finding — and statements
 * that already carry a Condition (ExternalId, PrincipalOrgID, ...) are
 * treated as deliberately scoped and not flagged.
 */
export const iamCrossAccountTrust: Rule = {
  metadata: {
    ruleId: 'iam-cross-account-trust',
    name: 'IAM Cross-Account Trust',
    description:
      'Detects IAM roles whose trust policy grants assume rights to a literal AWS account with no scoping condition.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::IAM::Role'],
    awsDocUrl:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html',
    remediationSteps: [
      'Verify the trusted account is intentional and documented',
      'Add a Condition (e.g. sts:ExternalId for third parties, aws:PrincipalOrgID for your org) to scope the trust',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
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
      const accounts = new Set<string>();
      for (const statement of statements) {
        if (statement.Effect !== 'Allow' || statement.Condition) {
          continue;
        }
        for (const account of accountIdsFromPrincipal(statement.Principal)) {
          accounts.add(account);
        }
      }
      if (accounts.size > 0) {
        report(resourceId, {
          issue: `IAM role trust policy grants assume rights to account(s) ${[...accounts].join(', ')} with no scoping condition.`,
          recommendation:
            'Confirm the cross-account trust is intentional and add a Condition (sts:ExternalId or aws:PrincipalOrgID) to scope it.',
        });
      }
    }
  },

  example: {
    flagged: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnRole(this, 'Role', {
  assumeRolePolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::999988887777:root' },
        Action: 'sts:AssumeRole',
      },
    ],
  },
});`,
    fixed: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnRole(this, 'Role', {
  assumeRolePolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::999988887777:root' },
        Action: 'sts:AssumeRole',
        Condition: {
          StringEquals: { 'sts:ExternalId': 'partner-integration-42' },
        },
      },
    ],
  },
});`,
  },
};
