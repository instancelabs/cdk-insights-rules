import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { elasticacheEncryptionDisabled } from './elasticacheEncryptionDisabled';

describe('elasticache-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [elasticacheEncryptionDisabled]);

  it('flags a replication group missing both encryption settings (two findings)', () => {
    const findings = run({
      Resources: {
        Cache: {
          Type: 'AWS::ElastiCache::ReplicationGroup',
          Properties: { ReplicationGroupDescription: 'x' },
        },
      },
    });
    expect(findings).toHaveLength(2);
  });

  it('does not flag a fully encrypted replication group', () => {
    expect(
      run({
        Resources: {
          Cache: {
            Type: 'AWS::ElastiCache::ReplicationGroup',
            Properties: {
              ReplicationGroupDescription: 'x',
              AtRestEncryptionEnabled: true,
              TransitEncryptionEnabled: true,
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('flags a memcached cache cluster without transit encryption', () => {
    expect(
      run({
        Resources: {
          Cache: {
            Type: 'AWS::ElastiCache::CacheCluster',
            Properties: { Engine: 'memcached' },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag a redis cache cluster (transit not settable on that type)', () => {
    expect(
      run({
        Resources: {
          Cache: {
            Type: 'AWS::ElastiCache::CacheCluster',
            Properties: { Engine: 'redis' },
          },
        },
      })
    ).toHaveLength(0);
  });
});
