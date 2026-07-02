import { asStatements } from '../../policy.js';
import type { PolicyStatement } from '../../policy.js';
import type { Rule } from '../../types';

const isFalsy = (value: unknown): boolean =>
  value === false || value === 'false' || value === 'False';

const actionsCoverAllS3 = (action: unknown): boolean => {
  const actions =
    typeof action === 'string' ? [action] : Array.isArray(action) ? action : [];
  return actions.some((entry) => entry === '*' || entry === 's3:*');
};

/**
 * True when the Deny's Resource covers both the bucket and its objects — a
 * TLS Deny that misses one still leaves unencrypted access to the other.
 * Intrinsics and unparseable ARNs count as covering (can't be ruled out).
 */
const coversBucketAndObjects = (resource: unknown): boolean => {
  if (resource === undefined || resource === null) {
    return false;
  }
  const resources = Array.isArray(resource) ? resource : [resource];
  if (resources.length === 0) {
    return false;
  }
  let bucketLevel = false;
  let objectLevel = false;
  for (const item of resources) {
    if (typeof item !== 'string' || item === '*') {
      return true; // intrinsic or wildcard — can't rule out
    }
    const arnBody = item.split(':::')[1];
    if (arnBody === undefined) {
      return true; // unparseable — be safe
    }
    if (arnBody.includes('/')) {
      objectLevel = true;
    } else {
      bucketLevel = true;
    }
  }
  return bucketLevel && objectLevel;
};

const enforcesTls = (statement: PolicyStatement): boolean => {
  if (statement.Effect !== 'Deny') {
    return false;
  }
  const condition = statement.Condition as Record<string, unknown> | undefined;
  const boolCondition = (condition?.Bool ?? condition?.BoolIfExists) as
    | Record<string, unknown>
    | undefined;
  if (!boolCondition || !isFalsy(boolCondition['aws:SecureTransport'])) {
    return false;
  }
  return (
    actionsCoverAllS3(statement.Action) &&
    coversBucketAndObjects(statement.Resource)
  );
};

/**
 * s3-bucket-policy-non-ssl
 *
 * A bucket that already carries a policy should also enforce TLS: a Deny on
 * `aws:SecureTransport = false` covering all S3 actions on the bucket and its
 * objects (what CDK's `enforceSSL: true` emits). Only buckets that *have* a
 * BucketPolicy are checked — the rule scopes to the resource that can carry
 * the statement.
 */
export const s3BucketPolicyNonSsl: Rule = {
  metadata: {
    ruleId: 's3-bucket-policy-non-ssl',
    name: 'S3 Bucket Policy Does Not Enforce TLS',
    description:
      'Detects S3 bucket policies without a Deny statement for non-TLS (aws:SecureTransport=false) requests.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::S3::BucketPolicy'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html#enforce-tls',
    remediationSteps: [
      'Add a Deny statement with Condition Bool aws:SecureTransport=false over s3:* on the bucket and its objects (in CDK: enforceSSL: true)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::S3::BucketPolicy') {
        continue;
      }
      const statements = asStatements(resource.Properties?.PolicyDocument);
      if (!statements.some(enforcesTls)) {
        report(resourceId, {
          issue:
            'S3 bucket policy does not deny non-TLS requests (no aws:SecureTransport=false Deny covering the bucket and its objects).',
          recommendation:
            'Add the TLS-enforcement Deny statement (in CDK, set enforceSSL: true on the bucket) so requests over plain HTTP are rejected.',
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
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::my-bucket/*',
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
        Resource: ['arn:aws:s3:::my-bucket', 'arn:aws:s3:::my-bucket/*'],
        Condition: { Bool: { 'aws:SecureTransport': 'false' } },
      },
    ],
  },
});`,
  },
};
