import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * eks-private-endpoint-access-disabled
 *
 * With only the public endpoint enabled, node-to-API-server traffic leaves
 * the VPC and hairpins over the internet. Private access keeps cluster
 * control traffic inside the VPC (and is the prerequisite for eventually
 * disabling public access).
 */
export const eksPrivateEndpointAccessDisabled: Rule = {
  metadata: {
    ruleId: 'eks-private-endpoint-access-disabled',
    name: 'EKS Private Endpoint Access Disabled',
    description:
      'Detects EKS clusters with public API access but no private endpoint access.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EKS::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html',
    remediationSteps: [
      'Set ResourcesVpcConfig.EndpointPrivateAccess to true so node/API traffic stays inside the VPC',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EKS::Cluster') {
        continue;
      }
      const vpcConfig = resource.Properties?.ResourcesVpcConfig;
      const publicEnabled =
        asBoolean(vpcConfig?.EndpointPublicAccess) !== false; // default true
      if (
        publicEnabled &&
        asBoolean(vpcConfig?.EndpointPrivateAccess) !== true
      ) {
        report(resourceId, {
          issue:
            'EKS cluster has only public endpoint access enabled — node-to-API traffic leaves the VPC.',
          recommendation:
            'Enable EndpointPrivateAccess so cluster control traffic stays inside the VPC.',
        });
      }
    }
  },

  example: {
    flagged: `import * as eks from 'aws-cdk-lib/aws-eks';

new eks.CfnCluster(this, 'Cluster', {
  roleArn: 'arn:aws:iam::111122223333:role/eks-cluster-role',
  resourcesVpcConfig: {
    subnetIds: ['subnet-12345678', 'subnet-87654321'],
    endpointPublicAccess: true,
    publicAccessCidrs: ['203.0.113.0/24'],
  },
});`,
    fixed: `import * as eks from 'aws-cdk-lib/aws-eks';

new eks.CfnCluster(this, 'Cluster', {
  roleArn: 'arn:aws:iam::111122223333:role/eks-cluster-role',
  resourcesVpcConfig: {
    subnetIds: ['subnet-12345678', 'subnet-87654321'],
    endpointPublicAccess: true,
    endpointPrivateAccess: true,
    publicAccessCidrs: ['203.0.113.0/24'],
  },
});`,
  },
};
