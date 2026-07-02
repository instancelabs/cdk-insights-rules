import type { Rule } from '../../types';

/**
 * lambda-vpc-nat-cost
 *
 * VPC-attached Lambdas in a stack that also runs a NAT gateway route their
 * AWS-service traffic through it — hourly plus per-GB charges for calls
 * that VPC endpoints would carry free.
 */
export const lambdaVpcNatCost: Rule = {
  metadata: {
    ruleId: 'lambda-vpc-nat-cost',
    name: 'Lambda VPC NAT Cost',
    description:
      'Detects VPC-attached Lambda functions in templates with a NAT gateway, where NAT data-processing charges accumulate.',
    severity: 'MEDIUM',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::Lambda::Function'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html',
    remediationSteps: [
      'Evaluate whether the function needs VPC attachment at all',
      'Add VPC endpoints (S3/DynamoDB gateway endpoints are free) so AWS-service traffic bypasses the NAT gateway',
    ],
  },

  check: (template, report) => {
    const resources = template.Resources ?? {};
    const hasNatGateway = Object.values(resources).some(
      (resource) => resource.Type === 'AWS::EC2::NatGateway'
    );
    if (!hasNatGateway) {
      return;
    }
    for (const [resourceId, resource] of Object.entries(resources)) {
      if (resource.Type !== 'AWS::Lambda::Function') {
        continue;
      }
      const subnetIds = resource.Properties?.VpcConfig?.SubnetIds;
      if (Array.isArray(subnetIds) && subnetIds.length > 0) {
        report(resourceId, {
          issue:
            'VPC-attached Lambda function shares a template with a NAT gateway — its AWS-service traffic is metered through NAT.',
          recommendation:
            'Confirm VPC attachment is required, and add VPC endpoints for the AWS services the function calls so traffic bypasses NAT data-processing charges.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';

new ec2.CfnNatGateway(this, 'Nat', {
  subnetId: 'subnet-12345678',
  allocationId: 'eipalloc-12345678',
});
new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
  vpcConfig: {
    subnetIds: ['subnet-12345678'],
    securityGroupIds: ['sg-12345678'],
  },
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';

new ec2.CfnNatGateway(this, 'Nat', {
  subnetId: 'subnet-12345678',
  allocationId: 'eipalloc-12345678',
});
new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
});`,
  },
};
