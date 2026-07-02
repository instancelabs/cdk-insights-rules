import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ec2InstancePublicIp } from './ec2InstancePublicIp';

describe('ec2-instance-public-ip', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ec2InstancePublicIp]);

  const instance = (networkInterfaces?: unknown): CfnTemplate => ({
    Resources: {
      Instance: {
        Type: 'AWS::EC2::Instance',
        Properties: networkInterfaces
          ? { NetworkInterfaces: networkInterfaces }
          : {},
      },
    },
  });

  it('flags an interface associating a public IP', () => {
    expect(
      run(instance([{ DeviceIndex: '0', AssociatePublicIpAddress: true }]))
    ).toHaveLength(1);
  });

  it('flags the CloudFormation string form "true"', () => {
    expect(
      run(instance([{ DeviceIndex: '0', AssociatePublicIpAddress: 'true' }]))
    ).toHaveLength(1);
  });

  it('does not flag interfaces without public IP association', () => {
    expect(
      run(instance([{ DeviceIndex: '0', AssociatePublicIpAddress: false }]))
    ).toHaveLength(0);
    expect(run(instance([{ DeviceIndex: '0' }]))).toHaveLength(0);
    expect(run(instance())).toHaveLength(0);
  });
});
