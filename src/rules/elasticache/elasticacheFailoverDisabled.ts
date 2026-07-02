import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * elasticache-failover-disabled
 *
 * A replication group with replicas but no automatic failover keeps paying
 * for the replicas without getting the availability; failover without
 * Multi-AZ leaves all nodes in one AZ.
 */
export const elasticacheFailoverDisabled: Rule = {
  metadata: {
    ruleId: 'elasticache-failover-disabled',
    name: 'ElastiCache Failover Disabled',
    description:
      'Detects ElastiCache replication groups with replicas but no automatic failover, or failover without Multi-AZ.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html',
    remediationSteps: [
      'Set AutomaticFailoverEnabled to true when replicas exist',
      'Enable MultiAZEnabled so nodes span availability zones',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ElastiCache::ReplicationGroup') {
        continue;
      }
      const props = resource.Properties ?? {};
      const failover = asBoolean(props.AutomaticFailoverEnabled);
      const numNodeGroups =
        typeof props.NumNodeGroups === 'number' ? props.NumNodeGroups : 1;
      const replicasPerNodeGroup =
        typeof props.ReplicasPerNodeGroup === 'number'
          ? props.ReplicasPerNodeGroup
          : 0;
      const numCacheClusters =
        typeof props.NumCacheClusters === 'number' ? props.NumCacheClusters : 1;
      const hasReplicas =
        numNodeGroups > 1 || replicasPerNodeGroup > 0 || numCacheClusters > 1;

      if (hasReplicas && failover !== true) {
        report(resourceId, {
          issue:
            'ElastiCache replication group has replicas but automatic failover is not enabled.',
          recommendation:
            'Enable AutomaticFailoverEnabled so a replica is promoted automatically when the primary fails.',
        });
      }
      if (failover === true && asBoolean(props.MultiAZEnabled) !== true) {
        report(resourceId, {
          issue:
            'ElastiCache replication group has automatic failover but Multi-AZ is not enabled.',
          recommendation:
            'Enable MultiAZEnabled so primary and replicas are distributed across availability zones.',
        });
      }
    }
  },

  example: {
    flagged: `import * as elasticache from 'aws-cdk-lib/aws-elasticache';

new elasticache.CfnReplicationGroup(this, 'Cache', {
  replicationGroupDescription: 'app cache',
  engine: 'redis',
  cacheNodeType: 'cache.t3.micro',
  numCacheClusters: 2,
});`,
    fixed: `import * as elasticache from 'aws-cdk-lib/aws-elasticache';

new elasticache.CfnReplicationGroup(this, 'Cache', {
  replicationGroupDescription: 'app cache',
  engine: 'redis',
  cacheNodeType: 'cache.t3.micro',
  numCacheClusters: 2,
  automaticFailoverEnabled: true,
  multiAzEnabled: true,
});`,
  },
};
