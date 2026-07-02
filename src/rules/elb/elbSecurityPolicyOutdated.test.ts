import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { elbSecurityPolicyOutdated } from './elbSecurityPolicyOutdated';

describe('elb-security-policy-outdated', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [elbSecurityPolicyOutdated]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: {
        Type: 'AWS::ElasticLoadBalancingV2::Listener',
        Properties: { ...properties },
      },
    },
  });

  it('flags outdated policies and the implicit default on HTTPS listeners', () => {
    expect(
      run(
        res({
          Protocol: 'HTTPS',
          SslPolicy: 'ELBSecurityPolicy-TLS-1-0-2015-04',
        })
      )
    ).toHaveLength(1);
    const defaultFindings = run(res({ Protocol: 'HTTPS' }));
    expect(defaultFindings).toHaveLength(1);
    expect(defaultFindings[0].issue).toContain('default');
  });

  it('does not flag modern policies or non-TLS listeners', () => {
    expect(
      run(
        res({
          Protocol: 'HTTPS',
          SslPolicy: 'ELBSecurityPolicy-TLS13-1-2-2021-06',
        })
      )
    ).toHaveLength(0);
    expect(run(res({ Protocol: 'HTTP' }))).toHaveLength(0);
  });
});
