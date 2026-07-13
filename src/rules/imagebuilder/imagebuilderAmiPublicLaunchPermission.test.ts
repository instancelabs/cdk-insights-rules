import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { imagebuilderAmiPublicLaunchPermission } from './imagebuilderAmiPublicLaunchPermission';

describe('imagebuilder-ami-public-launch-permission', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [imagebuilderAmiPublicLaunchPermission]);

  const distribution = (amiConfiguration: object): CfnTemplate => ({
    Resources: {
      Dist: {
        Type: 'AWS::ImageBuilder::DistributionConfiguration',
        Properties: {
          Name: 'app-ami',
          Distributions: [
            {
              Region: 'eu-west-2',
              AmiDistributionConfiguration: amiConfiguration,
            },
          ],
        },
      },
    },
  });

  it('flags a distribution shared with all AWS accounts', () => {
    expect(
      run(
        distribution({ LaunchPermissionConfiguration: { UserGroups: ['all'] } })
      )
    ).toHaveLength(1);
  });

  it('handles the camelCase spelling of the user-authored blob', () => {
    expect(
      run(
        distribution({ launchPermissionConfiguration: { userGroups: ['all'] } })
      )
    ).toHaveLength(1);
  });

  it('does not flag account-scoped or organization sharing', () => {
    expect(
      run(
        distribution({
          LaunchPermissionConfiguration: { UserIds: ['111122223333'] },
        })
      )
    ).toHaveLength(0);
    expect(run(distribution({}))).toHaveLength(0);
    expect(
      run({
        Resources: {
          Dist: {
            Type: 'AWS::ImageBuilder::DistributionConfiguration',
            Properties: { Name: 'app-ami' },
          },
        },
      })
    ).toHaveLength(0);
  });
});
