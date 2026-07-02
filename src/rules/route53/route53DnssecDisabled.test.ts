import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { route53DnssecDisabled } from './route53DnssecDisabled';

describe('route53-dnssec-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [route53DnssecDisabled]);

  it('flags a public zone without DNSSEC', () => {
    expect(
      run({
        Resources: {
          Zone: {
            Type: 'AWS::Route53::HostedZone',
            Properties: { Name: 'example.com' },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag a signed zone or a private zone', () => {
    expect(
      run({
        Resources: {
          Zone: {
            Type: 'AWS::Route53::HostedZone',
            Properties: { Name: 'example.com' },
          },
          Dnssec: {
            Type: 'AWS::Route53::DNSSEC',
            Properties: { HostedZoneId: { Ref: 'Zone' } },
          },
        },
      })
    ).toHaveLength(0);
    expect(
      run({
        Resources: {
          Private: {
            Type: 'AWS::Route53::HostedZone',
            Properties: {
              Name: 'internal.example.com',
              VPCs: [{ VPCId: 'vpc-1', VPCRegion: 'eu-west-2' }],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
