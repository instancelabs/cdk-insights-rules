import type { Rule } from '../../types';

const isNonEmptyArray = (value: unknown): boolean =>
  Array.isArray(value) && value.length > 0;

/**
 * iam-user-direct-policies
 *
 * CIS AWS Foundations 1.15: users must inherit permissions through groups
 * (or roles), not carry policies directly — per-user grants are unauditable
 * at scale.
 */
export const iamUserDirectPolicies: Rule = {
  metadata: {
    ruleId: 'iam-user-direct-policies',
    name: 'IAM User Direct Policies',
    description:
      'Detects IAM users with inline or managed policies attached directly instead of via groups.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::IAM::User'],
    awsDocUrl:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions',
    remediationSteps: [
      'Attach the policies to an IAM Group and add the user to the group (CIS 1.15)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::IAM::User') {
        continue;
      }
      const props = resource.Properties ?? {};
      if (isNonEmptyArray(props.Policies)) {
        report(resourceId, {
          issue: 'IAM user has inline policies attached directly.',
          recommendation:
            'Move the policies to an IAM Group and add the user to it — users must inherit permissions through groups (CIS 1.15).',
        });
      }
      if (isNonEmptyArray(props.ManagedPolicyArns)) {
        report(resourceId, {
          issue: 'IAM user has managed policies attached directly.',
          recommendation:
            'Attach the managed policies to an IAM Group and add the user to it (CIS 1.15).',
        });
      }
    }
  },

  example: {
    flagged: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnUser(this, 'User', {
  userName: 'deployer',
  managedPolicyArns: [
    'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess',
  ],
});`,
    fixed: `import * as iam from 'aws-cdk-lib/aws-iam';

new iam.CfnUser(this, 'User', {
  userName: 'deployer',
  groups: ['deployers'],
});`,
  },
};
