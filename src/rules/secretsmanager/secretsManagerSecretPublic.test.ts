import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { secretsManagerSecretPublic } from './secretsManagerSecretPublic';

const resourcePolicy = (
  statement: object,
  extra: object = {}
): CfnTemplate => ({
  Resources: {
    Policy: {
      Type: 'AWS::SecretsManager::ResourcePolicy',
      Properties: {
        SecretArn: 'arn:aws:secretsmanager:eu-west-2:1:secret:s',
        ResourcePolicy: { Version: '2012-10-17', Statement: [statement] },
        ...extra,
      },
    },
  },
});

describe('secrets-manager-secret-public', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [secretsManagerSecretPublic]);

  const publicStatement = {
    Effect: 'Allow',
    Principal: '*',
    Action: 'secretsmanager:GetSecretValue',
    Resource: '*',
  };

  it('flags a public resource policy', () => {
    expect(run(resourcePolicy(publicStatement))).toHaveLength(1);
  });

  it('handles a policy document given as a JSON string', () => {
    const template: CfnTemplate = {
      Resources: {
        Policy: {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretArn: 'arn:aws:secretsmanager:eu-west-2:1:secret:s',
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: publicStatement,
            }),
          },
        },
      },
    };
    expect(run(template)).toHaveLength(1);
  });

  it('does not flag when BlockPublicPolicy is true (rejected at deploy time)', () => {
    expect(
      run(resourcePolicy(publicStatement, { BlockPublicPolicy: true }))
    ).toHaveLength(0);
  });

  it('does not flag a scoped principal or a conditioned wildcard', () => {
    expect(
      run(
        resourcePolicy({
          ...publicStatement,
          Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        resourcePolicy({
          ...publicStatement,
          Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-abc' } },
        })
      )
    ).toHaveLength(0);
  });
});
