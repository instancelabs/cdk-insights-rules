import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eksPrivateEndpointAccessDisabled } from './eksPrivateEndpointAccessDisabled';

describe('eks-private-endpoint-access-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eksPrivateEndpointAccessDisabled]);

  const cluster = (vpcConfig: object): CfnTemplate => ({
    Resources: {
      Cluster: {
        Type: 'AWS::EKS::Cluster',
        Properties: { ResourcesVpcConfig: vpcConfig },
      },
    },
  });

  it('flags public-only endpoint access (default and explicit)', () => {
    expect(run(cluster({}))).toHaveLength(1);
    expect(
      run(cluster({ EndpointPublicAccess: true, EndpointPrivateAccess: false }))
    ).toHaveLength(1);
  });

  it('does not flag private access enabled or public disabled', () => {
    expect(run(cluster({ EndpointPrivateAccess: true }))).toHaveLength(0);
    expect(run(cluster({ EndpointPublicAccess: false }))).toHaveLength(0);
  });
});
