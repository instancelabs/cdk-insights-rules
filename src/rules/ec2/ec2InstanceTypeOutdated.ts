import type { Rule } from '../../types';

/**
 * ec2-instance-type-outdated
 *
 * t2 instances cost more than t3 for less performance — a leftover from
 * templates written before 2018.
 */
export const ec2InstanceTypeOutdated: Rule = {
  metadata: {
    ruleId: 'ec2-instance-type-outdated',
    name: 'EC2 Instance Type Outdated',
    description: 'Detects EC2 instances on the previous-generation t2 family.',
    severity: 'MEDIUM',
    wafPillar: 'Performance Efficiency',
    resourceTypes: ['AWS::EC2::Instance'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html',
    remediationSteps: [
      'Move to the equivalent t3 (or t4g for arm64) instance size',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::EC2::Instance') {
        continue;
      }
      const instanceType = resource.Properties?.InstanceType;
      if (typeof instanceType === 'string' && instanceType.startsWith('t2')) {
        report(resourceId, {
          issue: `EC2 instance uses previous-generation instance type ${instanceType}.`,
          recommendation:
            'Move to the equivalent t3/t4g size for better performance at lower cost.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnInstance(this, 'Instance', {
  imageId: 'ami-1234567890abcdef0',
  instanceType: 't2.large',
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnInstance(this, 'Instance', {
  imageId: 'ami-1234567890abcdef0',
  instanceType: 't3.large',
});`,
  },
};
