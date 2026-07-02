import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * elasticache-auth-token-missing
 *
 * A Redis replication group with transit encryption but neither an AUTH
 * token nor RBAC user groups encrypts the wire yet accepts any client that
 * reaches it. (Transit encryption is a prerequisite for AUTH, so the rule
 * only fires when it is decidably enabled.)
 */
export const elasticacheAuthTokenMissing: Rule = {
  metadata: {
    ruleId: 'elasticache-auth-token-missing',
    name: 'ElastiCache AUTH Token Missing',
    description:
      'Detects ElastiCache replication groups with transit encryption but no AUTH token or RBAC user groups.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html',
    remediationSteps: [
      'Attach RBAC user groups (UserGroupIds) — the modern replacement for AUTH tokens',
      'Or set AuthToken to require authentication on every connection',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ElastiCache::ReplicationGroup') {
        continue;
      }
      const props = resource.Properties ?? {};
      const hasRbac =
        Array.isArray(props.UserGroupIds) && props.UserGroupIds.length > 0;
      if (
        asBoolean(props.TransitEncryptionEnabled) === true &&
        !props.AuthToken &&
        !hasRbac
      ) {
        report(resourceId, {
          issue:
            'ElastiCache replication group has transit encryption but no AUTH token or RBAC user groups — any client that reaches it can connect.',
          recommendation:
            'Attach RBAC user groups (UserGroupIds) or set AuthToken so connections require authentication.',
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
  atRestEncryptionEnabled: true,
  transitEncryptionEnabled: true,
});`,
    fixed: `import * as elasticache from 'aws-cdk-lib/aws-elasticache';

new elasticache.CfnReplicationGroup(this, 'Cache', {
  replicationGroupDescription: 'app cache',
  engine: 'redis',
  cacheNodeType: 'cache.t3.micro',
  numCacheClusters: 1,
  atRestEncryptionEnabled: true,
  transitEncryptionEnabled: true,
  userGroupIds: ['app-users'],
});`,
  },
};
