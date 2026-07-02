import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * elasticache-encryption-disabled
 *
 * ElastiCache encrypts neither at rest nor in transit by default. Replication
 * groups are checked for both AtRestEncryptionEnabled and
 * TransitEncryptionEnabled; standalone cache clusters only support the
 * transit setting. Intrinsic values are undecidable and never flagged.
 */
export const elasticacheEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'elasticache-encryption-disabled',
    name: 'ElastiCache Encryption Disabled',
    description:
      'Detects ElastiCache replication groups and clusters without at-rest or in-transit encryption enabled.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::ElastiCache::ReplicationGroup',
      'AWS::ElastiCache::CacheCluster',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html',
    remediationSteps: [
      'Set AtRestEncryptionEnabled to true on the replication group',
      'Set TransitEncryptionEnabled to true so client traffic is encrypted',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    const isDisabled = (value: unknown): boolean =>
      !isIntrinsic(value) && asBoolean(value) !== true;

    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      const isReplicationGroup =
        resource.Type === 'AWS::ElastiCache::ReplicationGroup';
      const isCacheCluster = resource.Type === 'AWS::ElastiCache::CacheCluster';
      if (!isReplicationGroup && !isCacheCluster) {
        continue;
      }
      const props = resource.Properties ?? {};

      if (isReplicationGroup && isDisabled(props.AtRestEncryptionEnabled)) {
        report(resourceId, {
          issue:
            'ElastiCache replication group does not have encryption at rest enabled.',
          recommendation:
            'Set AtRestEncryptionEnabled to true to protect cached data at rest.',
        });
      }
      // On CacheCluster the transit property exists only for Memcached —
      // a Redis CacheCluster cannot set it (Redis needs a ReplicationGroup),
      // so flagging it would produce an unfixable finding.
      if (isCacheCluster && props.Engine !== 'memcached') {
        continue;
      }
      if (isDisabled(props.TransitEncryptionEnabled)) {
        report(resourceId, {
          issue:
            'ElastiCache cluster does not have encryption in transit enabled.',
          recommendation:
            'Set TransitEncryptionEnabled to true so data is encrypted between clients and the cache.',
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
  numCacheClusters: 1,
});`,
    fixed: `import * as elasticache from 'aws-cdk-lib/aws-elasticache';

new elasticache.CfnReplicationGroup(this, 'Cache', {
  replicationGroupDescription: 'app cache',
  engine: 'redis',
  cacheNodeType: 'cache.t3.micro',
  numCacheClusters: 1,
  atRestEncryptionEnabled: true,
  transitEncryptionEnabled: true,
});`,
  },
};
