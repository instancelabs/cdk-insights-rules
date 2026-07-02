import { asStatements, findSelfLockoutAction } from '../../policy.js';
import type { Rule } from '../../types';

const LOCKOUT_ACTIONS = new Set([
  '*',
  's3:*',
  's3:DeleteBucket',
  's3:DeleteBucketPolicy',
  's3:PutBucketPolicy',
]);

/**
 * True when a Deny's Resource covers the bucket itself (not only objects).
 * A Deny scoped purely to object ARNs (`arn:...:bucket/key`) can't block
 * PutBucketPolicy, so it can't lock the account out. Unparseable or intrinsic
 * resources are treated as covering — a lockout we can't rule out is a lockout
 * worth reviewing.
 */
const coversBucketLevel = (resource: unknown): boolean => {
  if (resource === undefined || resource === null) {
    return true;
  }
  const resources = Array.isArray(resource) ? resource : [resource];
  if (resources.length === 0) {
    return true;
  }
  for (const item of resources) {
    if (typeof item !== 'string') {
      return true; // intrinsic — can't rule out
    }
    if (item === '*') {
      return true;
    }
    const arnBody = item.split(':::')[1];
    if (arnBody === undefined || !arnBody.includes('/')) {
      return true; // unparseable or bucket-level ARN
    }
  }
  return false;
};

/**
 * s3-bucket-policy-self-lockout
 *
 * A bucket policy that Denies `s3:*` (or PutBucketPolicy/DeleteBucketPolicy)
 * to `Principal: '*'` with no carveout for the account root or an admin role
 * locks the account out of its own bucket — recovery means breaking glass on
 * root credentials, and AWS Support will typically not intervene. The
 * standard TLS-enforcement Deny (aws:SecureTransport=false) is exempt: it
 * denies only non-TLS requests.
 */
export const s3BucketPolicySelfLockout: Rule = {
  metadata: {
    ruleId: 's3-bucket-policy-self-lockout',
    name: 'S3 Bucket Policy Self-Lockout',
    description:
      'Detects bucket policies whose blanket Deny statements would lock the account out of its own bucket.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::S3::BucketPolicy'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html',
    remediationSteps: [
      'Add a Condition with StringNotEquals/ArnNotLike on aws:PrincipalArn exempting your admin role(s) or the account root',
      'If the Deny is meant to enforce TLS, scope it with a Bool aws:SecureTransport=false condition instead of a blanket Deny',
    ],
    complianceFrameworks: ['SOC2', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::S3::BucketPolicy') {
        continue;
      }
      const statements = asStatements(resource.Properties?.PolicyDocument);
      const matched = statements
        .filter((statement) => coversBucketLevel(statement.Resource))
        .map((statement) => findSelfLockoutAction(statement, LOCKOUT_ACTIONS))
        .find((action) => action !== undefined);
      if (matched) {
        report(resourceId, {
          issue: `Bucket policy Denies ${matched} to Principal '*' with no carveout for the account root or an admin role, locking the account out of the bucket.`,
          recommendation:
            "Exempt your admin role(s) via a Condition (e.g. ArnNotLike on aws:PrincipalArn), or scope the Deny — recovery from a full lockout requires the account root's credentials.",
        });
      }
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucketPolicy(this, 'Policy', {
  bucket: 'my-bucket',
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: 'arn:aws:s3:::my-bucket',
      },
    ],
  },
});`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucketPolicy(this, 'Policy', {
  bucket: 'my-bucket',
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: 'arn:aws:s3:::my-bucket',
        Condition: { Bool: { 'aws:SecureTransport': 'false' } },
      },
    ],
  },
});`,
  },
};
