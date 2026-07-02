import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { iamPoliciesOverlyPermissive } from './iamPoliciesOverlyPermissive';

const role = (statement: object): CfnTemplate => ({
  Resources: {
    Role: {
      Type: 'AWS::IAM::Role',
      Properties: {
        Policies: [
          {
            PolicyName: 'app',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [statement],
            },
          },
        ],
      },
    },
  },
});

describe('iam-policies-overly-permissive', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [iamPoliciesOverlyPermissive]);

  it('flags Action * on Resource * as administrative access', () => {
    const findings = run(role({ Effect: 'Allow', Action: '*', Resource: '*' }));
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('administrative');
  });

  it('flags a bare wildcard action or resource individually', () => {
    expect(
      run(role({ Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::b/*' }))
    ).toHaveLength(1);
    expect(
      run(role({ Effect: 'Allow', Action: ['s3:GetObject'], Resource: '*' }))
    ).toHaveLength(1);
  });

  it('scans standalone and managed policies, including JSON-string documents', () => {
    const findings = run({
      Resources: {
        Standalone: {
          Type: 'AWS::IAM::Policy',
          Properties: {
            PolicyName: 'p',
            PolicyDocument: JSON.stringify({
              Version: '2012-10-17',
              Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
            }),
          },
        },
        Managed: {
          Type: 'AWS::IAM::ManagedPolicy',
          Properties: {
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
            },
          },
        },
      },
    });
    expect(findings.map((finding) => finding.resourceId).sort()).toEqual([
      'Managed',
      'Standalone',
    ]);
  });

  it('does not flag scoped statements, service:* actions, or Deny wildcards', () => {
    expect(
      run(
        role({
          Effect: 'Allow',
          Action: ['s3:GetObject'],
          Resource: 'arn:aws:s3:::b/*',
        })
      )
    ).toHaveLength(0);
    expect(
      run(role({ Effect: 'Allow', Action: 's3:*', Resource: 'arn:aws:s3:::b' }))
    ).toHaveLength(0);
    expect(
      run(role({ Effect: 'Deny', Action: '*', Resource: '*' }))
    ).toHaveLength(0);
  });
});
