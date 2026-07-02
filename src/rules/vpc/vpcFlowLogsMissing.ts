import type { Rule } from '../../types';

/**
 * vpc-flow-logs-missing
 *
 * Without flow logs there is no record of network traffic for incident
 * forensics. A VPC counts as covered when an AWS::EC2::FlowLog in the same
 * template targets it (by Ref or literal id).
 */
export const vpcFlowLogsMissing: Rule = {
  metadata: {
    ruleId: 'vpc-flow-logs-missing',
    name: 'VPC Flow Logs Missing',
    description: 'Detects VPCs without flow logs configured.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::EC2::VPC', 'AWS::EC2::FlowLog'],
    awsDocUrl:
      'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html',
    remediationSteps: [
      'Add an AWS::EC2::FlowLog targeting the VPC (in CDK: vpc.addFlowLog())',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    const entries = Object.entries(template.Resources ?? {});

    const coveredVpcIds = new Set<string>();
    for (const [, resource] of entries) {
      if (resource.Type !== 'AWS::EC2::FlowLog') {
        continue;
      }
      if (resource.Properties?.ResourceType !== 'VPC') {
        continue;
      }
      const target = resource.Properties?.ResourceId;
      if (typeof target === 'string') {
        coveredVpcIds.add(target);
      } else if (typeof target?.Ref === 'string') {
        coveredVpcIds.add(target.Ref);
      }
    }

    for (const [resourceId, resource] of entries) {
      if (resource.Type !== 'AWS::EC2::VPC') {
        continue;
      }
      if (!coveredVpcIds.has(resourceId)) {
        report(resourceId, {
          issue: 'VPC does not have flow logs enabled.',
          recommendation:
            'Add a flow log for the VPC (in CDK: vpc.addFlowLog()) so network traffic is recorded for security analysis and forensics.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnVPC(this, 'Vpc', {
  cidrBlock: '10.0.0.0/16',
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

const vpc = new ec2.CfnVPC(this, 'Vpc', {
  cidrBlock: '10.0.0.0/16',
});
new ec2.CfnFlowLog(this, 'FlowLog', {
  resourceType: 'VPC',
  resourceId: vpc.ref,
  trafficType: 'ALL',
  logDestinationType: 's3',
  logDestination: 'arn:aws:s3:::my-flow-logs',
});`,
  },
};
