import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { mskBrokerLoggingDisabled } from './mskBrokerLoggingDisabled';

describe('msk-broker-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [mskBrokerLoggingDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::MSK::Cluster', Properties: { ...properties } },
    },
  });

  it('flags a cluster without broker logs', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('does not flag any enabled destination', () => {
    expect(
      run(
        res({
          LoggingInfo: { BrokerLogs: { CloudWatchLogs: { Enabled: true } } },
        })
      )
    ).toHaveLength(0);
    expect(
      run(res({ LoggingInfo: { BrokerLogs: { S3: { Enabled: true } } } }))
    ).toHaveLength(0);
  });
});
