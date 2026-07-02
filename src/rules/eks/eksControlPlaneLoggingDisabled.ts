import type { Rule } from '../../types';

const RECOMMENDED_LOG_TYPES = [
  'api',
  'audit',
  'authenticator',
  'controllerManager',
  'scheduler',
];

/**
 * eks-control-plane-logging-disabled
 *
 * EKS control-plane logging is off by default; without at least the audit
 * and authenticator logs there is no record of who did what to the cluster.
 */
export const eksControlPlaneLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'eks-control-plane-logging-disabled',
    name: 'EKS Control Plane Logging Disabled',
    description:
      'Detects EKS clusters with missing control-plane log types (api, audit, authenticator, controllerManager, scheduler).',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EKS::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html',
    remediationSteps: [
      'Enable all control-plane log types in Logging.ClusterLogging.EnabledTypes (in CDK: clusterLogging)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EKS::Cluster') {
        continue;
      }
      const enabledTypes =
        resource.Properties?.Logging?.ClusterLogging?.EnabledTypes;
      const enabled = Array.isArray(enabledTypes)
        ? enabledTypes
            .map((entry) => entry?.Type)
            .filter((type): type is string => typeof type === 'string')
        : [];
      const missing = RECOMMENDED_LOG_TYPES.filter(
        (type) => !enabled.includes(type)
      );
      if (missing.length > 0) {
        report(resourceId, {
          issue: `EKS cluster is missing control-plane logging for: ${missing.join(', ')}.`,
          recommendation:
            'Enable all control-plane log types (api, audit, authenticator, controllerManager, scheduler) so cluster activity is auditable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as eks from 'aws-cdk-lib/aws-eks';

new eks.CfnCluster(this, 'Cluster', {
  roleArn: 'arn:aws:iam::111122223333:role/eks-cluster-role',
  resourcesVpcConfig: {
    subnetIds: ['subnet-12345678', 'subnet-87654321'],
  },
});`,
    fixed: `import * as eks from 'aws-cdk-lib/aws-eks';

new eks.CfnCluster(this, 'Cluster', {
  roleArn: 'arn:aws:iam::111122223333:role/eks-cluster-role',
  resourcesVpcConfig: {
    subnetIds: ['subnet-12345678', 'subnet-87654321'],
  },
  logging: {
    clusterLogging: {
      enabledTypes: [
        { type: 'api' },
        { type: 'audit' },
        { type: 'authenticator' },
        { type: 'controllerManager' },
        { type: 'scheduler' },
      ],
    },
  },
});`,
  },
};
