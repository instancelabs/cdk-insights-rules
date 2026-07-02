import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecsContainerPrivileged } from './ecsContainerPrivileged';

describe('ecs-container-privileged', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecsContainerPrivileged]).map(
      (finding) => finding.ruleId
    );

  it('flags a task definition with a privileged container', () => {
    expect(
      run({
        Resources: {
          TaskDef: {
            Type: 'AWS::ECS::TaskDefinition',
            Properties: {
              ContainerDefinitions: [{ Name: 'app', Privileged: true }],
            },
          },
        },
      })
    ).toContain('ecs-container-privileged');
  });

  it('flags the CloudFormation string form "true" and names the container', () => {
    const findings = runRules(
      {
        Resources: {
          TaskDef: {
            Type: 'AWS::ECS::TaskDefinition',
            Properties: {
              ContainerDefinitions: [
                { Name: 'app', Privileged: 'true' },
                { Name: 'sidecar', Privileged: false },
              ],
            },
          },
        },
      },
      [ecsContainerPrivileged]
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('app');
    expect(findings[0].issue).not.toContain('sidecar');
  });

  it('does not flag a task definition whose containers are all not privileged', () => {
    expect(
      run({
        Resources: {
          TaskDef: {
            Type: 'AWS::ECS::TaskDefinition',
            Properties: {
              ContainerDefinitions: [{ Name: 'app', Privileged: false }],
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag a task definition with no ContainerDefinitions', () => {
    expect(
      run({
        Resources: {
          TaskDef: {
            Type: 'AWS::ECS::TaskDefinition',
            Properties: {},
          },
        },
      })
    ).toHaveLength(0);
  });
});
