import type { Rule } from '../../types';

/**
 * ecs-resources-missing
 *
 * Containers with neither task-level nor container-level CPU/memory limits
 * can starve their neighbours on EC2 launch types. Fargate task definitions
 * always carry task-level sizing and are exempt by construction.
 */
export const ecsResourcesMissing: Rule = {
  metadata: {
    ruleId: 'ecs-resources-missing',
    name: 'ECS Container Resource Limits Missing',
    description:
      'Detects ECS containers with no CPU or memory limits and no task-level sizing.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size',
    remediationSteps: [
      'Set task-level Cpu and Memory, or per-container Memory/MemoryReservation and Cpu',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECS::TaskDefinition') {
        continue;
      }
      const props = resource.Properties ?? {};
      const hasTaskSizing =
        (props.Cpu !== undefined && props.Cpu !== null && props.Cpu !== '') ||
        (props.Memory !== undefined &&
          props.Memory !== null &&
          props.Memory !== '');
      if (hasTaskSizing) {
        continue;
      }
      const containers = Array.isArray(props.ContainerDefinitions)
        ? props.ContainerDefinitions
        : [];
      const unbounded = containers
        .filter(
          (container) =>
            !container?.Memory &&
            !container?.MemoryReservation &&
            !container?.Cpu
        )
        .map((container) => container?.Name ?? '(unnamed)');
      if (unbounded.length > 0) {
        report(resourceId, {
          issue: `ECS task definition has containers with no CPU or memory limits: ${unbounded.join(', ')}.`,
          recommendation:
            'Define task-level Cpu/Memory or per-container limits so a runaway container cannot starve the host.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  containerDefinitions: [
    { name: 'app', image: 'public.ecr.aws/nginx/nginx:latest' },
  ],
});`,
    fixed: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  cpu: '256',
  memory: '512',
  containerDefinitions: [
    { name: 'app', image: 'public.ecr.aws/nginx/nginx:latest' },
  ],
});`,
  },
};
