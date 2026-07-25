import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaEnvSensitiveData } from './lambdaEnvSensitiveData';

describe('lambda-env-sensitive-data', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaEnvSensitiveData]);

  const fn = (variables: object): CfnTemplate => ({
    Resources: {
      Fn: {
        Type: 'AWS::Lambda::Function',
        Properties: { Environment: { Variables: variables } },
      },
    },
  });

  it('flags sensitive keys with literal values (snake_case and camelCase)', () => {
    const findings = run(fn({ DB_PASSWORD: 'hunter2', apiKey: 'abc123' }));
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('DB_PASSWORD');
    expect(findings[0].issue).toContain('apiKey');
  });

  it('does not flag benign names or non-literal values', () => {
    expect(run(fn({ TABLE_NAME: 'users', LOG_LEVEL: 'info' }))).toHaveLength(0);
    expect(run(fn({ DB_PASSWORD: { Ref: 'SecretParam' } }))).toHaveLength(0);
  });

  it('does not flag pointer-shaped values (ARN, SSM path, dynamic reference, URL)', () => {
    expect(
      run(
        fn({
          DB_SECRET:
            'arn:aws:secretsmanager:eu-west-2:111122223333:secret:db-abc123',
          API_KEY: '/prod/api-key',
          DB_PASSWORD:
            '{{resolve:secretsmanager:prod/db:SecretString:password}}',
          TOKEN_ENDPOINT_SECRET: 'https://auth.example.com/token',
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag keys that name a pointer to a secret', () => {
    expect(
      run(
        fn({
          SECRET_ARN: 'db-secret-arn-placeholder',
          API_KEY_PARAMETER_NAME: 'prod-api-key',
          TOKEN_PATH: 'auth.token',
        })
      )
    ).toHaveLength(0);
  });

  it('still flags literal secrets that resemble none of the pointer shapes', () => {
    expect(run(fn({ API_KEY: 'sk-live-4242424242' }))).toHaveLength(1);
    expect(run(fn({ SIGNING_KEY: 'c2VjcmV0LXNpZ25pbmcta2V5' }))).toHaveLength(
      1
    );
  });
});
