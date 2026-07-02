import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { opensearchAccessControlWeak } from './opensearchAccessControlWeak';

describe('opensearch-access-control-weak', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [opensearchAccessControlWeak]);

  const domain = (properties: object): CfnTemplate => ({
    Resources: {
      Domain: {
        Type: 'AWS::OpenSearchService::Domain',
        Properties: properties,
      },
    },
  });

  it('flags a domain missing both controls (two findings)', () => {
    expect(run(domain({}))).toHaveLength(2);
  });

  it('does not flag FGAC enabled and VPC deployment', () => {
    expect(
      run(
        domain({
          AdvancedSecurityOptions: { Enabled: true },
          VPCOptions: { SubnetIds: ['subnet-1'] },
        })
      )
    ).toHaveLength(0);
  });
});
