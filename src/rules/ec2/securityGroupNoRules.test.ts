import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { securityGroupNoRules } from './securityGroupNoRules';

describe('security-group-no-rules', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [securityGroupNoRules]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: {
        Type: 'AWS::EC2::SecurityGroup',
        Properties: { GroupDescription: 'x', ...properties },
      },
    },
  });

  it('flags a group with no rules', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('does not flag groups with ingress or egress rules', () => {
    expect(
      run(res({ SecurityGroupIngress: [{ IpProtocol: 'tcp' }] }))
    ).toHaveLength(0);
    expect(
      run(res({ SecurityGroupEgress: [{ IpProtocol: '-1' }] }))
    ).toHaveLength(0);
  });
});
