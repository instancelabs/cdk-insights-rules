import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { wafLoggingDisabled } from './wafLoggingDisabled';

describe('waf-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [wafLoggingDisabled]);

  const acl = {
    Type: 'AWS::WAFv2::WebACL',
    Properties: {
      Scope: 'REGIONAL',
      DefaultAction: { Block: {} },
      VisibilityConfig: { CloudWatchMetricsEnabled: true },
    },
  };

  it('flags a WebACL without a logging configuration', () => {
    expect(run({ Resources: { Acl: acl } })).toHaveLength(1);
  });

  it('does not flag a WebACL referenced by a logging configuration', () => {
    expect(
      run({
        Resources: {
          Acl: acl,
          Logging: {
            Type: 'AWS::WAFv2::LoggingConfiguration',
            Properties: {
              ResourceArn: { 'Fn::GetAtt': ['Acl', 'Arn'] },
              LogDestinationConfigs: ['arn:logs'],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
