import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eksControlPlaneLoggingDisabled } from './eksControlPlaneLoggingDisabled';

describe('eks-control-plane-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eksControlPlaneLoggingDisabled]);

  const cluster = (properties: object): CfnTemplate => ({
    Resources: {
      Cluster: { Type: 'AWS::EKS::Cluster', Properties: properties },
    },
  });

  it('flags a cluster with no logging and names the missing types', () => {
    const findings = run(cluster({}));
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).toContain('audit');
  });

  it('flags partially enabled logging', () => {
    const findings = run(
      cluster({
        Logging: { ClusterLogging: { EnabledTypes: [{ Type: 'api' }] } },
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].issue).not.toContain('api,');
  });

  it('does not flag all five log types enabled', () => {
    expect(
      run(
        cluster({
          Logging: {
            ClusterLogging: {
              EnabledTypes: [
                { Type: 'api' },
                { Type: 'audit' },
                { Type: 'authenticator' },
                { Type: 'controllerManager' },
                { Type: 'scheduler' },
              ],
            },
          },
        })
      )
    ).toHaveLength(0);
  });
});
