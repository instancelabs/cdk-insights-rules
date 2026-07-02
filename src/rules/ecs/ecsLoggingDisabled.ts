import type { Rule } from '../../types';

/**
 * ecs-logging-disabled
 *
 * A container without a LogConfiguration writes stdout/stderr to nowhere —
 * the first debugging session finds nothing.
 */
export const ecsLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'ecs-logging-disabled',
    name: 'ECS Container Logging Disabled',
    description: 'Detects ECS containers without a log configuration.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html',
    remediationSteps: [
      'Set LogConfiguration with the awslogs driver on every container definition',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECS::TaskDefinition') {
        continue;
      }
      const containers = resource.Properties?.ContainerDefinitions;
      if (!Array.isArray(containers)) {
        continue;
      }
      const unlogged = containers
        .filter((container) => !container?.LogConfiguration?.LogDriver)
        .map((container) => container?.Name ?? '(unnamed)');
      if (unlogged.length > 0) {
        report(resourceId, {
          issue: `ECS task definition has containers with no logging configuration: ${unlogged.join(', ')}.`,
          recommendation:
            'Configure LogConfiguration (awslogs driver) so container output reaches CloudWatch.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  cpu: '256',
  memory: '512',
  containerDefinitions: [
    { name: 'app', image: 'public.ecr.aws/nginx/nginx:latest' },
  ],
});`,
    fixed: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  cpu: '256',
  memory: '512',
  containerDefinitions: [
    {
      name: 'app',
      image: 'public.ecr.aws/nginx/nginx:latest',
      logConfiguration: {
        logDriver: 'awslogs',
        options: {
          'awslogs-group': '/ecs/app',
          'awslogs-region': 'eu-west-2',
          'awslogs-stream-prefix': 'app',
        },
      },
    },
  ],
});`,
  },
};
