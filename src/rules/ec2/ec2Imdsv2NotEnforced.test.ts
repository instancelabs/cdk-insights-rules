import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ec2Imdsv2NotEnforced } from './ec2Imdsv2NotEnforced';

describe('ec2-imdsv2-not-enforced', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ec2Imdsv2NotEnforced]).map((finding) => finding.ruleId);

  it('flags a LaunchTemplate with no MetadataOptions', () => {
    expect(
      run({
        Resources: {
          Lt: {
            Type: 'AWS::EC2::LaunchTemplate',
            Properties: { LaunchTemplateData: {} },
          },
        },
      })
    ).toContain('ec2-imdsv2-not-enforced');
  });

  it('flags a LaunchTemplate with HttpTokens optional', () => {
    expect(
      run({
        Resources: {
          Lt: {
            Type: 'AWS::EC2::LaunchTemplate',
            Properties: {
              LaunchTemplateData: {
                MetadataOptions: { HttpTokens: 'optional' },
              },
            },
          },
        },
      })
    ).toContain('ec2-imdsv2-not-enforced');
  });

  it('does not flag a LaunchTemplate with HttpTokens required', () => {
    expect(
      run({
        Resources: {
          Lt: {
            Type: 'AWS::EC2::LaunchTemplate',
            Properties: {
              LaunchTemplateData: {
                MetadataOptions: { HttpTokens: 'required' },
              },
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('flags a LaunchConfiguration with HttpTokens optional', () => {
    expect(
      run({
        Resources: {
          Lc: {
            Type: 'AWS::AutoScaling::LaunchConfiguration',
            Properties: { MetadataOptions: { HttpTokens: 'optional' } },
          },
        },
      })
    ).toContain('ec2-imdsv2-not-enforced');
  });

  it('does not flag a LaunchConfiguration with HttpTokens required', () => {
    expect(
      run({
        Resources: {
          Lc: {
            Type: 'AWS::AutoScaling::LaunchConfiguration',
            Properties: { MetadataOptions: { HttpTokens: 'required' } },
          },
        },
      })
    ).toHaveLength(0);
  });
});
