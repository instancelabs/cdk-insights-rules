import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ecs-service-connect-access-logs-missing
 *
 * Service Connect proxies all inter-service traffic; without a log
 * configuration that traffic is invisible to audit and incident response.
 */
export const ecsServiceConnectAccessLogsMissing: Rule = {
  metadata: {
    ruleId: 'ecs-service-connect-access-logs-missing',
    name: 'ECS Service Connect Access Logs Missing',
    description:
      'Detects ECS services with Service Connect enabled but no log configuration.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ECS::Service'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-connect-logging.html',
    remediationSteps: [
      'Set ServiceConnectConfiguration.LogConfiguration with a LogDriver (e.g. awslogs)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECS::Service') {
        continue;
      }
      const serviceConnect = resource.Properties?.ServiceConnectConfiguration;
      if (asBoolean(serviceConnect?.Enabled) !== true) {
        continue;
      }
      if (!serviceConnect?.LogConfiguration?.LogDriver) {
        report(resourceId, {
          issue:
            'ECS Service Connect is enabled without an access log configuration.',
          recommendation:
            'Configure ServiceConnectConfiguration.LogConfiguration with a LogDriver (e.g. awslogs) so inter-service traffic is auditable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnService(this, 'Service', {
  cluster: 'my-cluster',
  serviceConnectConfiguration: {
    enabled: true,
    namespace: 'internal',
  },
});`,
    fixed: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnService(this, 'Service', {
  cluster: 'my-cluster',
  serviceConnectConfiguration: {
    enabled: true,
    namespace: 'internal',
    logConfiguration: {
      logDriver: 'awslogs',
      options: {
        'awslogs-group': '/ecs/service-connect',
        'awslogs-region': 'eu-west-2',
        'awslogs-stream-prefix': 'sc',
      },
    },
  },
});`,
  },
};
