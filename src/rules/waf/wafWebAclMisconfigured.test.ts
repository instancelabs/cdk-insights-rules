import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { wafWebAclMisconfigured } from './wafWebAclMisconfigured';

describe('waf-webacl-misconfigured', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [wafWebAclMisconfigured]);

  const webAcl = (properties: object): CfnTemplate => ({
    Resources: {
      Acl: { Type: 'AWS::WAFv2::WebACL', Properties: properties },
    },
  });

  it('flags default-allow with no rules, and disabled metrics', () => {
    const findings = run(
      webAcl({
        DefaultAction: { Allow: {} },
        VisibilityConfig: { CloudWatchMetricsEnabled: false },
      })
    );
    expect(findings).toHaveLength(2);
  });

  it('does not flag default-allow with managed rules and metrics on', () => {
    expect(
      run(
        webAcl({
          DefaultAction: { Allow: {} },
          Rules: [{ Name: 'managed', Priority: 0 }],
          VisibilityConfig: { CloudWatchMetricsEnabled: true },
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag a default-block WebACL with metrics', () => {
    expect(
      run(
        webAcl({
          DefaultAction: { Block: {} },
          VisibilityConfig: { CloudWatchMetricsEnabled: true },
        })
      )
    ).toHaveLength(0);
  });
});
