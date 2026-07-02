import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { elbHttpsListenersMissing } from './elbHttpsListenersMissing';

const listener = (properties: object): CfnTemplate => ({
  Resources: {
    Listener: {
      Type: 'AWS::ElasticLoadBalancingV2::Listener',
      Properties: properties,
    },
  },
});

describe('elb-https-listeners-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [elbHttpsListenersMissing]);

  it('flags an HTTP listener that forwards traffic', () => {
    expect(
      run(
        listener({
          Protocol: 'HTTP',
          Port: 80,
          DefaultActions: [{ Type: 'forward', TargetGroupArn: 'arn' }],
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag an HTTP listener that redirects to HTTPS', () => {
    expect(
      run(
        listener({
          Protocol: 'HTTP',
          Port: 80,
          DefaultActions: [
            { Type: 'redirect', RedirectConfig: { Protocol: 'HTTPS' } },
          ],
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag an HTTPS listener', () => {
    expect(
      run(
        listener({
          Protocol: 'HTTPS',
          Port: 443,
          Certificates: [{ CertificateArn: 'arn' }],
          DefaultActions: [{ Type: 'forward', TargetGroupArn: 'arn' }],
        })
      )
    ).toHaveLength(0);
  });
});
