import { asStatements, findSelfLockoutAction } from '../../policy.js';
import type { Rule } from '../../types';

const LOCKOUT_ACTIONS = new Set([
  '*',
  'sns:*',
  'sns:DeleteTopic',
  'sns:RemovePermission',
]);

/**
 * sns-topic-policy-self-lockout
 *
 * A topic policy that Denies `sns:*` (or the permission-management actions)
 * to `Principal: '*'` with no root/admin carveout locks the account out of
 * managing its own topic. The standard TLS-enforcement Deny is exempt.
 */
export const snsTopicPolicySelfLockout: Rule = {
  metadata: {
    ruleId: 'sns-topic-policy-self-lockout',
    name: 'SNS Topic Policy Self-Lockout',
    description:
      'Detects SNS topic policies whose blanket Deny statements would lock the account out of its own topic.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::SNS::TopicPolicy'],
    awsDocUrl:
      'https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-key-concepts.html',
    remediationSteps: [
      'Exempt your admin role(s) or the account root from the Deny via a Condition (e.g. ArnNotLike on aws:PrincipalArn)',
      'If the Deny is meant to enforce TLS, scope it with a Bool aws:SecureTransport=false condition',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::SNS::TopicPolicy') {
        continue;
      }
      const statements = asStatements(resource.Properties?.PolicyDocument);
      const matched = statements
        .map((statement) => findSelfLockoutAction(statement, LOCKOUT_ACTIONS))
        .find((action) => action !== undefined);
      if (matched) {
        report(resourceId, {
          issue: `Topic policy Denies ${matched} to Principal '*' with no carveout for the account root or an admin role, locking the account out of the topic.`,
          recommendation:
            'Exempt your admin role(s) via a Condition (e.g. ArnNotLike on aws:PrincipalArn), or scope the Deny to the specific principals it targets.',
        });
      }
    }
  },

  example: {
    flagged: `import * as sns from 'aws-cdk-lib/aws-sns';

new sns.CfnTopicPolicy(this, 'Policy', {
  topics: ['arn:aws:sns:eu-west-2:111122223333:my-topic'],
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Deny',
        Principal: '*',
        Action: 'sns:*',
        Resource: 'arn:aws:sns:eu-west-2:111122223333:my-topic',
      },
    ],
  },
});`,
    fixed: `import * as sns from 'aws-cdk-lib/aws-sns';

new sns.CfnTopicPolicy(this, 'Policy', {
  topics: ['arn:aws:sns:eu-west-2:111122223333:my-topic'],
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Deny',
        Principal: '*',
        Action: 'sns:*',
        Resource: 'arn:aws:sns:eu-west-2:111122223333:my-topic',
        Condition: { Bool: { 'aws:SecureTransport': 'false' } },
      },
    ],
  },
});`,
  },
};
