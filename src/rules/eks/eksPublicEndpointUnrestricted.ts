import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * eks-public-endpoint-unrestricted
 *
 * EKS enables public API-server access by default. A public endpoint with no
 * PublicAccessCidrs restriction (or an explicit 0.0.0.0/0) exposes the
 * Kubernetes API to the whole internet.
 */
export const eksPublicEndpointUnrestricted: Rule = {
  metadata: {
    ruleId: 'eks-public-endpoint-unrestricted',
    name: 'EKS Public Endpoint Unrestricted',
    description:
      'Detects EKS clusters whose public API endpoint is reachable from the whole internet (no PublicAccessCidrs restriction).',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EKS::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html',
    remediationSteps: [
      'Restrict PublicAccessCidrs to the specific IP ranges that need API access',
      'Or disable EndpointPublicAccess and enable EndpointPrivateAccess, reaching the API via VPN/bastion',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EKS::Cluster') {
        continue;
      }
      const vpcConfig = resource.Properties?.ResourcesVpcConfig;
      // Public access defaults to true when unset.
      const publicAccessEnabled =
        asBoolean(vpcConfig?.EndpointPublicAccess) !== false;
      if (!publicAccessEnabled) {
        continue;
      }
      const cidrs = vpcConfig?.PublicAccessCidrs;
      const unrestricted =
        !Array.isArray(cidrs) ||
        cidrs.length === 0 ||
        cidrs.includes('0.0.0.0/0');
      if (unrestricted) {
        report(resourceId, {
          issue:
            'EKS cluster public API endpoint is reachable from the whole internet (no PublicAccessCidrs restriction).',
          recommendation:
            'Restrict PublicAccessCidrs to known IP ranges, or disable public access and use the private endpoint via VPN/bastion.',
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
  },
});`,
    fixed: `import * as eks from 'aws-cdk-lib/aws-eks';

new eks.CfnCluster(this, 'Cluster', {
  roleArn: 'arn:aws:iam::111122223333:role/eks-cluster-role',
  resourcesVpcConfig: {
    subnetIds: ['subnet-12345678', 'subnet-87654321'],
    endpointPublicAccess: true,
    publicAccessCidrs: ['203.0.113.0/24'],
  },
});`,
  },
};
