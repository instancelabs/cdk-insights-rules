import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { elasticacheAuthTokenMissing } from './elasticacheAuthTokenMissing';

describe('elasticache-auth-token-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [elasticacheAuthTokenMissing]);

  const group = (properties: object): CfnTemplate => ({
    Resources: {
      Cache: {
        Type: 'AWS::ElastiCache::ReplicationGroup',
        Properties: { ReplicationGroupDescription: 'x', ...properties },
      },
    },
  });

  it('flags transit encryption without auth', () => {
    expect(run(group({ TransitEncryptionEnabled: true }))).toHaveLength(1);
  });

  it('does not flag when an AUTH token or RBAC groups are set', () => {
    expect(
      run(group({ TransitEncryptionEnabled: true, AuthToken: 'token-value' }))
    ).toHaveLength(0);
    expect(
      run(
        group({ TransitEncryptionEnabled: true, UserGroupIds: ['app-users'] })
      )
    ).toHaveLength(0);
  });

  it('does not fire without transit encryption (AUTH requires it)', () => {
    expect(run(group({}))).toHaveLength(0);
  });
});
