import type { Rule } from '../../types';

/**
 * nat-gateway-usage
 *
 * Informational: each NAT gateway bills hourly plus per-GB processed. The
 * finding exists so the cost is a decision, not a surprise.
 */
export const natGatewayUsage: Rule = {
  metadata: {
    ruleId: 'nat-gateway-usage',
    name: 'NAT Gateway Usage',
    description:
      'Flags NAT gateways so their hourly and per-GB costs are a conscious decision.',
    severity: 'LOW',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::EC2::NatGateway'],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html',
    remediationSteps: [
      'Use gateway VPC endpoints (free) for S3/DynamoDB and interface endpoints for chatty AWS services',
      'Consider one NAT gateway per VPC (not per AZ) for non-critical environments, or IPv6 egress-only gateways',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type === 'AWS::EC2::NatGateway') {
        report(resourceId, {
          issue:
            'NAT gateway incurs hourly charges plus per-GB data processing.',
          recommendation:
            'Route AWS-service traffic through VPC endpoints and confirm the NAT gateway count matches what the environment actually needs.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnNatGateway(this, 'Nat', {
  subnetId: 'subnet-12345678',
  allocationId: 'eipalloc-12345678',
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnVPCEndpoint(this, 'S3Endpoint', {
  vpcId: 'vpc-12345678',
  serviceName: 'com.amazonaws.eu-west-2.s3',
  vpcEndpointType: 'Gateway',
});`,
  },
};
