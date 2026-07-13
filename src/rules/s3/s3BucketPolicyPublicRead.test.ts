import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3BucketPolicyPublicRead } from './s3BucketPolicyPublicRead';

describe('s3-bucket-policy-public-read', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3BucketPolicyPublicRead]);

  const policy = (statement: object): CfnTemplate => ({
    Resources: {
      Policy: {
        Type: 'AWS::S3::BucketPolicy',
        Properties: {
          Bucket: 'assets',
          PolicyDocument: { Version: '2012-10-17', Statement: [statement] },
        },
      },
    },
  });

  it('flags Allow + wildcard principal + object read', () => {
    expect(
      run(
        policy({
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::assets/*',
        })
      )
    ).toHaveLength(1);
    expect(
      run(
        policy({
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: ['s3:GetObject', 's3:ListBucket'],
          Resource: '*',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag scoped, service-principal, non-read, or Deny statements', () => {
    expect(
      run(
        policy({
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-abc123' } },
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        policy({
          Effect: 'Allow',
          Principal: { Service: 'cloudfront.amazonaws.com' },
          Action: 's3:GetObject',
          Resource: '*',
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        policy({
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:PutObject',
          Resource: '*',
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        policy({
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
        })
      )
    ).toHaveLength(0);
  });
});
