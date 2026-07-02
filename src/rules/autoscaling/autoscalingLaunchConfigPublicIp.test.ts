import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { autoscalingLaunchConfigPublicIp } from './autoscalingLaunchConfigPublicIp';

const launchConfig = (properties: object): CfnTemplate => ({
  Resources: {
    Lc: {
      Type: 'AWS::AutoScaling::LaunchConfiguration',
      Properties: properties,
    },
  },
});

describe('autoscaling-launch-config-public-ip', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [autoscalingLaunchConfigPublicIp]);

  it('flags AssociatePublicIpAddress true (boolean or string form)', () => {
    expect(run(launchConfig({ AssociatePublicIpAddress: true }))).toHaveLength(
      1
    );
    expect(
      run(launchConfig({ AssociatePublicIpAddress: 'true' }))
    ).toHaveLength(1);
  });

  it('does not flag false, absent, or intrinsic values', () => {
    expect(run(launchConfig({ AssociatePublicIpAddress: false }))).toHaveLength(
      0
    );
    expect(run(launchConfig({}))).toHaveLength(0);
    expect(
      run(
        launchConfig({
          AssociatePublicIpAddress: { 'Fn::If': ['X', true, false] },
        })
      )
    ).toHaveLength(0);
  });
});
