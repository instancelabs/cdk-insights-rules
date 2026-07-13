import {
  actionsAsArray,
  asStatements,
  isPublicStatement,
} from '../../policy.js';
import type { Rule } from '../../types';

/**
 * s3-bucket-policy-public-read
 *
 * A bucket policy with Allow + wildcard Principal + an object-read action and
 * no scoping condition is a deliberately (or catastrophically) public bucket.
 * This is orthogonal to Block Public Access absence: it flags the explicit
 * public grant itself. Statements scoped by aws:SourceArn/PrincipalOrgID etc.
 * are not public (see isPublicStatement); Deny statements never match.
 */

const READ_ACTION = /^(\*|s3:\*|s3:Get\*|s3:GetObject.*)$/i;

export const s3BucketPolicyPublicRead: Rule = {
  metadata: {
    ruleId: 's3-bucket-policy-public-read',
    name: 'S3 Bucket Policy Grants Public Read',
    description:
      'Detects S3 bucket policies that allow object reads to a wildcard principal with no scoping condition — the bucket contents are publicly downloadable.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::S3::BucketPolicy'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html',
    remediationSteps: [
      'Serve public content through CloudFront with Origin Access Control and scope the bucket policy to the distribution (Principal cloudfront.amazonaws.com + aws:SourceArn condition)',
      'For genuinely public datasets, keep the grant but acknowledge it explicitly by suppressing this rule on the bucket policy resource',
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
      const grantsPublicRead = statements.some(
        (statement) =>
          isPublicStatement(statement) &&
          actionsAsArray(statement.Action).some((action) =>
            READ_ACTION.test(action)
          )
      );
      if (grantsPublicRead) {
        report(resourceId, {
          issue:
            'Bucket policy allows object reads to a wildcard principal with no scoping condition — the bucket is publicly readable.',
          recommendation:
            'Front public content with CloudFront Origin Access Control and scope the policy to the distribution ARN; if the bucket is intentionally public, suppress this rule to record the decision.',
        });
      }
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

const bucket = new s3.Bucket(this, 'Assets');

new s3.CfnBucketPolicy(this, 'Policy', {
  bucket: bucket.bucketName,
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: bucket.arnForObjects('*'),
      },
    ],
  },
});`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

const bucket = new s3.Bucket(this, 'Assets');

new s3.CfnBucketPolicy(this, 'Policy', {
  bucket: bucket.bucketName,
  policyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { Service: 'cloudfront.amazonaws.com' },
        Action: 's3:GetObject',
        Resource: bucket.arnForObjects('*'),
        Condition: {
          StringEquals: {
            'aws:SourceArn':
              'arn:aws:cloudfront::111122223333:distribution/EDFDVBD6EXAMPLE',
          },
        },
      },
    ],
  },
});`,
  },
};
