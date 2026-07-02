import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { elasticacheFailoverDisabled } from './elasticacheFailoverDisabled';

describe('elasticache-failover-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [elasticacheFailoverDisabled]);

  const group = (properties: object): CfnTemplate => ({
    Resources: {
      Cache: {
        Type: 'AWS::ElastiCache::ReplicationGroup',
        Properties: { ReplicationGroupDescription: 'x', ...properties },
      },
    },
  });

  it('flags replicas without automatic failover', () => {
    expect(run(group({ NumCacheClusters: 2 }))).toHaveLength(1);
    expect(run(group({ ReplicasPerNodeGroup: 1 }))).toHaveLength(1);
  });

  it('flags failover without Multi-AZ', () => {
    const findings = run(
      group({ NumCacheClusters: 2, AutomaticFailoverEnabled: true })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('Multi-AZ');
  });

  it('does not flag failover with Multi-AZ, or single-node groups', () => {
    expect(
      run(
        group({
          NumCacheClusters: 2,
          AutomaticFailoverEnabled: true,
          MultiAZEnabled: true,
        })
      )
    ).toHaveLength(0);
    expect(run(group({ NumCacheClusters: 1 }))).toHaveLength(0);
  });
});
