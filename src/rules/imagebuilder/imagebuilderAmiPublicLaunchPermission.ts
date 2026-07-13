import type { Rule } from '../../types';

/**
 * imagebuilder-ami-public-launch-permission
 *
 * An AMI distribution with LaunchPermissionConfiguration.UserGroups
 * containing "all" shares the produced image with EVERY AWS account —
 * a classic data-exfiltration path (baked-in credentials, agents, code).
 * The AmiDistributionConfiguration blob is user-authored JSON, so both
 * PascalCase (raw CFN) and camelCase spellings are checked.
 */

// biome-ignore lint/suspicious/noExplicitAny: templates are arbitrary JSON
const prop = (object: any, pascal: string, camel: string): any =>
  object?.[pascal] ?? object?.[camel];

// biome-ignore lint/suspicious/noExplicitAny: templates are arbitrary JSON
const sharesWithAllAccounts = (distribution: any): boolean => {
  const amiConfiguration = prop(
    distribution,
    'AmiDistributionConfiguration',
    'amiDistributionConfiguration'
  );
  const launchPermission = prop(
    amiConfiguration,
    'LaunchPermissionConfiguration',
    'launchPermissionConfiguration'
  );
  const userGroups = prop(launchPermission, 'UserGroups', 'userGroups');
  return Array.isArray(userGroups) && userGroups.includes('all');
};

export const imagebuilderAmiPublicLaunchPermission: Rule = {
  metadata: {
    ruleId: 'imagebuilder-ami-public-launch-permission',
    name: 'Image Builder AMI Shared With All AWS Accounts',
    description:
      'Detects Image Builder distribution configurations whose AMI launch permission includes the "all" user group, making the produced AMI public to every AWS account.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ImageBuilder::DistributionConfiguration'],
    awsDocUrl:
      'https://docs.aws.amazon.com/imagebuilder/latest/userguide/manage-distribution-settings.html',
    remediationSteps: [
      'Remove UserGroups: ["all"] from LaunchPermissionConfiguration',
      'Share with specific accounts via TargetAccountIds or LaunchPermissionConfiguration.UserIds, or with your organization via OrganizationArns',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ImageBuilder::DistributionConfiguration') {
        continue;
      }
      const distributions = resource.Properties?.Distributions;
      if (!Array.isArray(distributions)) {
        continue;
      }
      if (distributions.some(sharesWithAllAccounts)) {
        report(resourceId, {
          issue:
            'Image Builder distribution shares the produced AMI with all AWS accounts (LaunchPermissionConfiguration UserGroups includes "all").',
          recommendation:
            'Share the AMI only with specific accounts (UserIds / TargetAccountIds) or your organization (OrganizationArns) — a public AMI exposes everything baked into the image.',
        });
      }
    }
  },

  example: {
    flagged: `import * as imagebuilder from 'aws-cdk-lib/aws-imagebuilder';

new imagebuilder.CfnDistributionConfiguration(this, 'Dist', {
  name: 'app-ami',
  distributions: [
    {
      region: 'eu-west-2',
      amiDistributionConfiguration: {
        Name: 'app-ami-{{ imagebuilder:buildDate }}',
        LaunchPermissionConfiguration: { UserGroups: ['all'] },
      },
    },
  ],
});`,
    fixed: `import * as imagebuilder from 'aws-cdk-lib/aws-imagebuilder';

new imagebuilder.CfnDistributionConfiguration(this, 'Dist', {
  name: 'app-ami',
  distributions: [
    {
      region: 'eu-west-2',
      amiDistributionConfiguration: {
        Name: 'app-ami-{{ imagebuilder:buildDate }}',
        LaunchPermissionConfiguration: { UserIds: ['111122223333'] },
      },
    },
  ],
});`,
  },
};
