import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ecs-deployment-circuit-breaker-disabled
 *
 * Without the circuit breaker, a failed rolling deployment keeps launching
 * broken tasks instead of stopping and rolling back. Only applies to the
 * ECS deployment controller.
 */
export const ecsDeploymentCircuitBreakerDisabled: Rule = {
  metadata: {
    ruleId: 'ecs-deployment-circuit-breaker-disabled',
    name: 'ECS Deployment Circuit Breaker Disabled',
    description:
      'Detects ECS services without the deployment circuit breaker enabled.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::ECS::Service'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html',
    remediationSteps: [
      'Set DeploymentConfiguration.DeploymentCircuitBreaker with Enable: true and Rollback: true',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECS::Service') {
        continue;
      }
      const controller = resource.Properties?.DeploymentController?.Type;
      if (controller && controller !== 'ECS') {
        continue; // CODE_DEPLOY / EXTERNAL manage their own rollback
      }
      const breaker =
        resource.Properties?.DeploymentConfiguration?.DeploymentCircuitBreaker;
      if (asBoolean(breaker?.Enable) !== true) {
        report(resourceId, {
          issue:
            'ECS service does not enable the deployment circuit breaker — a failed rolling deployment will not stop or roll back automatically.',
          recommendation:
            'Enable DeploymentCircuitBreaker with Rollback: true so failed deployments revert to the last healthy task set.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnService(this, 'Service', {
  cluster: 'my-cluster',
});`,
    fixed: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnService(this, 'Service', {
  cluster: 'my-cluster',
  deploymentConfiguration: {
    deploymentCircuitBreaker: { enable: true, rollback: true },
  },
});`,
  },
};
