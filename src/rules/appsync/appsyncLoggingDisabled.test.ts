import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { appsyncLoggingDisabled } from './appsyncLoggingDisabled';

describe('appsync-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [appsyncLoggingDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: {
        Type: 'AWS::AppSync::GraphQLApi',
        Properties: {
          Name: 'api',
          AuthenticationType: 'AWS_IAM',
          ...properties,
        },
      },
    },
  });

  it('flags missing logging and X-Ray (two findings)', () => {
    expect(run(res({}))).toHaveLength(2);
  });

  it('flags field logging set to NONE', () => {
    const findings = run(
      res({ LogConfig: { FieldLogLevel: 'NONE' }, XrayEnabled: true })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('field-level');
  });

  it('does not flag full logging plus X-Ray', () => {
    expect(
      run(res({ LogConfig: { FieldLogLevel: 'ERROR' }, XrayEnabled: true }))
    ).toHaveLength(0);
  });
});
