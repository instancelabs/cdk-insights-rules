import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { iamCrossAccountTrust } from './iamCrossAccountTrust';

describe('iam-cross-account-trust', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [iamCrossAccountTrust]);

  const role = (statement: object): CfnTemplate => ({
    Resources: {
      Role: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [statement],
          },
        },
      },
    },
  });

  it('flags unconditioned account trust (ARN and bare id) and names the account', () => {
    const findings = run(
      role({
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::999988887777:root' },
        Action: 'sts:AssumeRole',
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('999988887777');
    expect(
      run(
        role({
          Effect: 'Allow',
          Principal: { AWS: '999988887777' },
          Action: 'sts:AssumeRole',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag conditioned trust or service principals', () => {
    expect(
      run(
        role({
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::999988887777:root' },
          Action: 'sts:AssumeRole',
          Condition: { StringEquals: { 'sts:ExternalId': 'abc' } },
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        role({
          Effect: 'Allow',
          Principal: { Service: 'lambda.amazonaws.com' },
          Action: 'sts:AssumeRole',
        })
      )
    ).toHaveLength(0);
  });
});
