import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { route53QueryLoggingDisabled } from './route53QueryLoggingDisabled';

describe('route53-query-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [route53QueryLoggingDisabled]);

  it('flags a public zone without query logging', () => {
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

  it('recognizes inline and standalone query logging, and skips private zones', () => {
    expect(
      run({
        Resources: {
          Zone: {
            Type: 'AWS::Route53::HostedZone',
            Properties: {
              Name: 'example.com',
              QueryLoggingConfig: { CloudWatchLogsLogGroupArn: 'arn:lg' },
            },
          },
        },
      })
    ).toHaveLength(0);
    expect(
      run({
        Resources: {
          Zone: {
            Type: 'AWS::Route53::HostedZone',
            Properties: { Name: 'example.com' },
          },
          Logging: {
            Type: 'AWS::Route53::QueryLoggingConfig',
            Properties: {
              HostedZoneId: { Ref: 'Zone' },
              CloudWatchLogsLogGroupArn: 'arn:lg',
            },
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
