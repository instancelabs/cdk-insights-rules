import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eksPublicEndpointUnrestricted } from './eksPublicEndpointUnrestricted';

const cluster = (vpcConfig: object): CfnTemplate => ({
  Resources: {
    Cluster: {
      Type: 'AWS::EKS::Cluster',
      Properties: { ResourcesVpcConfig: vpcConfig },
    },
  },
});

describe('eks-public-endpoint-unrestricted', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eksPublicEndpointUnrestricted]);

  it('flags public access with no CIDR restriction (default and explicit)', () => {
    expect(run(cluster({}))).toHaveLength(1);
    expect(run(cluster({ EndpointPublicAccess: true }))).toHaveLength(1);
    expect(
      run(
        cluster({
          EndpointPublicAccess: true,
          PublicAccessCidrs: ['0.0.0.0/0'],
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag restricted CIDRs or a private-only endpoint', () => {
    expect(
      run(
        cluster({
          EndpointPublicAccess: true,
          PublicAccessCidrs: ['203.0.113.0/24'],
        })
      )
    ).toHaveLength(0);
    expect(
      run(cluster({ EndpointPublicAccess: false, EndpointPrivateAccess: true }))
    ).toHaveLength(0);
  });
});
