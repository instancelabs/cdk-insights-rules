import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ecs-container-privileged — flag privileged containers.
 *
 * A container running in privileged mode gets access to the host, so a
 * container compromise can escalate into a host compromise. We report the task
 * definition once if any of its container definitions sets `Privileged: true`.
 */
export const ecsContainerPrivileged: Rule = {
  metadata: {
    ruleId: 'ecs-container-privileged',
    name: 'ECS Container Running In Privileged Mode',
    description:
      'Detects ECS task definitions with a container running in privileged mode, which can access the host and escalate a container compromise into host compromise.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html',
    remediationSteps: [
      'Remove Privileged: true from the container definition unless strictly required',
      'Grant only the specific Linux capabilities the workload needs via LinuxParameters',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'NIST'],
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
      // asBoolean also catches the string "true", which CloudFormation accepts.
      const privileged = containers.filter(
        (container) => asBoolean(container?.Privileged) === true
      );
      if (privileged.length > 0) {
        const names = privileged
          .map((container) => container?.Name ?? '(unnamed)')
          .join(', ');
        report(resourceId, {
          issue: `ECS task definition has a container running in privileged mode: ${names}.`,
          recommendation:
            'Remove Privileged: true unless strictly required — a privileged container can access the host and turn a container compromise into host compromise.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  containerDefinitions: [
    {
      name: 'app',
      image: 'public.ecr.aws/nginx/nginx:latest',
      privileged: true,
    },
  ],
});`,
    fixed: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  containerDefinitions: [
    {
      name: 'app',
      image: 'public.ecr.aws/nginx/nginx:latest',
      privileged: false,
    },
  ],
});`,
  },
};
