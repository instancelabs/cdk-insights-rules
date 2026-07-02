import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { securityGroupUnrestrictedEgress } from './securityGroupUnrestrictedEgress';

describe('security-group-unrestricted-egress', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [securityGroupUnrestrictedEgress]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: {
        Type: 'AWS::EC2::SecurityGroup',
        Properties: { GroupDescription: 'x', ...properties },
      },
    },
  });

  it('flags egress open to the internet (v4 and v6)', () => {
    expect(
      run(
        res({
          SecurityGroupEgress: [{ IpProtocol: '-1', CidrIp: '0.0.0.0/0' }],
        })
      )
    ).toHaveLength(1);
    expect(
      run(
        res({ SecurityGroupEgress: [{ IpProtocol: '-1', CidrIpv6: '::/0' }] })
      )
    ).toHaveLength(1);
  });

  it('does not flag restricted egress or groups without egress rules', () => {
    expect(
      run(
        res({
          SecurityGroupEgress: [
            {
              IpProtocol: 'tcp',
              FromPort: 443,
              ToPort: 443,
              CidrIp: '10.0.0.0/16',
            },
          ],
        })
      )
    ).toHaveLength(0);
    expect(run(res({}))).toHaveLength(0);
  });
});
