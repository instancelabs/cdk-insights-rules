import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecsResourcesMissing } from './ecsResourcesMissing';

describe('ecs-resources-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecsResourcesMissing]);

  const taskDef = (properties: object): CfnTemplate => ({
    Resources: {
      TaskDef: { Type: 'AWS::ECS::TaskDefinition', Properties: properties },
    },
  });

  it('flags unbounded containers and names them', () => {
    const findings = run(
      taskDef({ ContainerDefinitions: [{ Name: 'app', Image: 'x' }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('app');
  });

  it('does not flag task-level sizing or container limits', () => {
    expect(
      run(
        taskDef({
          Cpu: '256',
          Memory: '512',
          ContainerDefinitions: [{ Name: 'app', Image: 'x' }],
        })
      )
    ).toHaveLength(0);
    expect(
      run(
        taskDef({
          ContainerDefinitions: [{ Name: 'app', Image: 'x', Memory: 512 }],
        })
      )
    ).toHaveLength(0);
  });
});
