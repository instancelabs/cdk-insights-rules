import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecsLoggingDisabled } from './ecsLoggingDisabled';

describe('ecs-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecsLoggingDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::ECS::TaskDefinition', Properties: { ...properties } },
    },
  });

  it('flags containers without logging and names them', () => {
    const findings = run(
      res({ ContainerDefinitions: [{ Name: 'app', Image: 'x' }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('app');
  });

  it('does not flag containers with a log driver', () => {
    expect(
      run(
        res({
          ContainerDefinitions: [
            {
              Name: 'app',
              Image: 'x',
              LogConfiguration: { LogDriver: 'awslogs' },
            },
          ],
        })
      )
    ).toHaveLength(0);
  });
});
