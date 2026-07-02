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
});
