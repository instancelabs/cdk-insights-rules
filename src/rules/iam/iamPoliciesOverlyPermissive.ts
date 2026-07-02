import { asStatements } from '../../policy.js';
import type { CfnResource, Rule } from '../../types';

const SCANNED_TYPES = new Set([
  'AWS::IAM::Policy',
  'AWS::IAM::Role',
  'AWS::IAM::ManagedPolicy',
]);

const hasBareWildcard = (value: unknown): boolean =>
  value === '*' || (Array.isArray(value) && value.includes('*'));

/** Every policy document attached to the resource, inline or direct. */
const policyDocumentsOf = (resource: CfnResource): unknown[] => {
  const documents: unknown[] = [];
  const inlinePolicies = resource.Properties?.Policies;
  if (Array.isArray(inlinePolicies)) {
    for (const policy of inlinePolicies) {
      if (policy?.PolicyDocument) {
        documents.push(policy.PolicyDocument);
      }
    }
  }
  if (resource.Properties?.PolicyDocument) {
    documents.push(resource.Properties.PolicyDocument);
  }
  return documents;
};

/**
 * iam-policies-overly-permissive
 *
 * Flags Allow statements with a bare `*` Action and/or a bare `*` Resource.
 * `Action: *` with `Resource: *` is administrative access; either alone is
 * still far beyond least privilege. Only the bare wildcard is flagged —
 * `service:*` actions and scoped ARNs are noisy-but-legitimate patterns this
 * rule deliberately ignores. Note: some AWS actions genuinely require
 * `Resource: '*'` (they support no resource-level permissions); suppress the
 * rule on those resources rather than widening the policy.
 */
export const iamPoliciesOverlyPermissive: Rule = {
  metadata: {
    ruleId: 'iam-policies-overly-permissive',
    name: 'IAM Overly Permissive Policies',
    description:
      'Detects IAM policies whose Allow statements use bare * wildcards for actions or resources.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::IAM::Policy',
      'AWS::IAM::Role',
      'AWS::IAM::ManagedPolicy',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege',
    remediationSteps: [
      'Replace wildcard (*) actions with the specific actions the workload needs',
      'Restrict Resource to specific ARNs instead of *',
      'Use IAM Access Analyzer to identify unused permissions',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (!SCANNED_TYPES.has(resource.Type)) {
        continue;
      }

      let wildcardAction = false;
      let wildcardResource = false;
      for (const document of policyDocumentsOf(resource)) {
        for (const statement of asStatements(document)) {
          if (statement.Effect !== 'Allow') {
            continue;
          }
          wildcardAction ||= hasBareWildcard(statement.Action);
          wildcardResource ||= hasBareWildcard(statement.Resource);
        }
      }

      if (wildcardAction && wildcardResource) {
        report(resourceId, {
          issue:
            'IAM policy allows all actions (*) on all resources (*) — administrative access.',
          recommendation:
            'Restrict both actions and resources to follow the principle of least privilege.',
        });
      } else if (wildcardAction) {
        report(resourceId, {
          issue: 'IAM policy allows all actions (*) — overly permissive.',
          recommendation:
            'Specify only the required actions instead of a bare wildcard.',
        });
      } else if (wildcardResource) {
        report(resourceId, {
          issue:
            'IAM policy allows actions on all resources (*) — overly permissive.',
          recommendation:
            'Restrict Resource to specific ARNs; if the action supports no resource-level permissions, suppress this rule on the resource instead.',
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
        Principal: { Service: 'lambda.amazonaws.com' },
        Action: 'sts:AssumeRole',
      },
    ],
  },
  policies: [
    {
      policyName: 'app',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
      },
    },
  ],
});`,
    fixed: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnRole(this, 'Role', {
  assumeRolePolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { Service: 'lambda.amazonaws.com' },
        Action: 'sts:AssumeRole',
      },
    ],
  },
  policies: [
    {
      policyName: 'app',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: ['s3:GetObject'],
            Resource: 'arn:aws:s3:::my-bucket/*',
          },
        ],
      },
    },
  ],
});`,
  },
};
