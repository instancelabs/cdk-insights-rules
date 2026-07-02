import { asStatements, findSelfLockoutAction } from '../../policy.js';
import type { Rule } from '../../types';

const LOCKOUT_ACTIONS = new Set([
  '*',
  'sqs:*',
  'sqs:DeleteQueue',
  'sqs:RemovePermission',
]);

/**
 * sqs-queue-policy-self-lockout
 *
 * A queue policy that Denies `sqs:*` (or the permission-management actions)
 * to `Principal: '*'` with no root/admin carveout locks the account out of
 * managing its own queue. The standard TLS-enforcement Deny that CDK's
 * `enforceSSL: true` emits (Deny with aws:SecureTransport=false) is exempt —
 * it denies only non-TLS requests.
 */
export const sqsQueuePolicySelfLockout: Rule = {
  metadata: {
    ruleId: 'sqs-queue-policy-self-lockout',
    name: 'SQS Queue Policy Self-Lockout',
    description:
      'Detects SQS queue policies whose blanket Deny statements would lock the account out of its own queue.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::SQS::QueuePolicy'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-access-policy-language-basic-structure.html',
    remediationSteps: [
      'Exempt your admin role(s) or the account root from the Deny via a Condition (e.g. ArnNotLike on aws:PrincipalArn)',
      'If the Deny is meant to enforce TLS, scope it with a Bool aws:SecureTransport=false condition (CDK: enforceSSL: true)',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::SQS::QueuePolicy') {
        continue;
      }
      const statements = asStatements(resource.Properties?.PolicyDocument);
      const matched = statements
        .map((statement) => findSelfLockoutAction(statement, LOCKOUT_ACTIONS))
        .find((action) => action !== undefined);
      if (matched) {
        report(resourceId, {
          issue: `Queue policy Denies ${matched} to Principal '*' with no carveout for the account root or an admin role, locking the account out of the queue.`,
          recommendation:
            'Exempt your admin role(s) via a Condition (e.g. ArnNotLike on aws:PrincipalArn), or scope the Deny to the specific principals it targets.',
        });
      }
    }
  },

  example: {
    flagged: `import * as sqs from 'aws-cdk-lib/aws-sqs';

new sqs.CfnQueuePolicy(this, 'Policy', {
  queues: ['https://sqs.eu-west-2.amazonaws.com/111122223333/my-queue'],
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Deny',
        Principal: '*',
        Action: 'sqs:*',
        Resource: 'arn:aws:sqs:eu-west-2:111122223333:my-queue',
      },
    ],
  },
});`,
    fixed: `import * as sqs from 'aws-cdk-lib/aws-sqs';

new sqs.CfnQueuePolicy(this, 'Policy', {
  queues: ['https://sqs.eu-west-2.amazonaws.com/111122223333/my-queue'],
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Deny',
        Principal: '*',
        Action: 'sqs:*',
        Resource: 'arn:aws:sqs:eu-west-2:111122223333:my-queue',
        Condition: { Bool: { 'aws:SecureTransport': 'false' } },
      },
    ],
  },
});`,
  },
};
