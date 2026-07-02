import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { route53HealthCheckSuboptimal } from './route53HealthCheckSuboptimal';

describe('route53-health-check-suboptimal', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [route53HealthCheckSuboptimal]);

  const healthCheck = (config: object): CfnTemplate => ({
    Resources: {
      Hc: {
        Type: 'AWS::Route53::HealthCheck',
        Properties: { HealthCheckConfig: config },
      },
    },
  });

  it('flags HTTP checks and standard intervals', () => {
    expect(run(healthCheck({ Type: 'HTTP' }))).toHaveLength(1);
    expect(
      run(healthCheck({ Type: 'HTTPS', RequestInterval: 30 }))
    ).toHaveLength(1);
  });

  it('does not flag HTTPS with a fast interval', () => {
    expect(
      run(healthCheck({ Type: 'HTTPS', RequestInterval: 10 }))
    ).toHaveLength(0);
    expect(run(healthCheck({ Type: 'TCP' }))).toHaveLength(0);
  });
});
