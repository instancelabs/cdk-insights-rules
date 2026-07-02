import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecsSecretsPlaintext } from './ecsSecretsPlaintext';

const taskDef = (environment: object[]): CfnTemplate => ({
  Resources: {
    TaskDef: {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [
          { Name: 'app', Image: 'nginx', Environment: environment },
        ],
      },
    },
  },
});

describe('ecs-secrets-plaintext', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecsSecretsPlaintext]);

  it('flags sensitive names (snake_case and camelCase) and lists them', () => {
    const findings = run(
      taskDef([
        { Name: 'DB_PASSWORD', Value: 'x' },
        { Name: 'apiKey', Value: 'y' },
        { Name: 'LOG_LEVEL', Value: 'info' },
      ])
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('DB_PASSWORD');
    expect(findings[0].issue).toContain('apiKey');
    expect(findings[0].issue).not.toContain('LOG_LEVEL');
  });

  it('does not flag benign environment variables', () => {
    expect(
      run([{ Name: 'NODE_ENV', Value: 'production' }] as never)
    ).toBeDefined();
    expect(
      run(taskDef([{ Name: 'NODE_ENV', Value: 'production' }]))
    ).toHaveLength(0);
  });

  it('does not flag the Secrets property (the right way)', () => {
    expect(
      run({
        Resources: {
          TaskDef: {
            Type: 'AWS::ECS::TaskDefinition',
            Properties: {
              ContainerDefinitions: [
                {
                  Name: 'app',
                  Image: 'nginx',
                  Secrets: [{ Name: 'DB_PASSWORD', ValueFrom: 'arn:...' }],
                },
              ],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
