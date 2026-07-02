import { isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ec2-imdsv2-not-enforced — launch templates / configurations that don't
 * require IMDSv2.
 *
 * When `MetadataOptions.HttpTokens` is not `"required"`, instances still answer
 * IMDSv1 requests. An SSRF flaw in an app can then read the instance metadata
 * service and exfiltrate the instance role credentials.
 */
export const ec2Imdsv2NotEnforced: Rule = {
  metadata: {
    ruleId: 'ec2-imdsv2-not-enforced',
    name: 'EC2 IMDSv2 Not Enforced',
    description:
      'Detects launch templates and launch configurations that do not require IMDSv2 (MetadataOptions.HttpTokens is not "required"), leaving instances exposed to SSRF-based credential theft.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::EC2::LaunchTemplate',
      'AWS::AutoScaling::LaunchConfiguration',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html',
    remediationSteps: [
      'Set MetadataOptions.HttpTokens to "required" on the launch template / launch configuration',
      'In CDK, pass requireImdsv2: true on the instance or launch template',
    ],
    complianceFrameworks: ['CIS', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      let httpTokens: unknown;

      if (resource.Type === 'AWS::EC2::LaunchTemplate') {
        httpTokens =
          resource.Properties?.LaunchTemplateData?.MetadataOptions?.HttpTokens;
      } else if (resource.Type === 'AWS::AutoScaling::LaunchConfiguration') {
        httpTokens = resource.Properties?.MetadataOptions?.HttpTokens;
      } else {
        continue;
      }

      // An intrinsic may resolve to "required" — undecidable, so never flag.
      if (httpTokens !== 'required' && !isIntrinsic(httpTokens)) {
        report(resourceId, {
          issue:
            'Launch template/configuration does not enforce IMDSv2 (MetadataOptions.HttpTokens is not set to "required").',
          recommendation:
            'Set MetadataOptions.HttpTokens to "required" so instances only accept IMDSv2 session-token requests, mitigating SSRF-based theft of instance credentials.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnLaunchTemplate(this, 'Lt', {
  launchTemplateData: {
    instanceType: 't3.micro',
  },
});`,
    fixed: `import * as ec2 from 'aws-cdk-lib/aws-ec2';

new ec2.CfnLaunchTemplate(this, 'Lt', {
  launchTemplateData: {
    instanceType: 't3.micro',
    metadataOptions: { httpTokens: 'required' },
  },
});`,
  },
};
