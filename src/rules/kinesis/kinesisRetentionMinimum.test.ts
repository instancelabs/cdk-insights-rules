import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { kinesisRetentionMinimum } from './kinesisRetentionMinimum';

describe('kinesis-retention-minimum', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [kinesisRetentionMinimum]);

  const stream = (properties: object): CfnTemplate => ({
    Resources: {
      Stream: { Type: 'AWS::Kinesis::Stream', Properties: properties },
    },
  });

  it('flags default and explicit 24-hour retention', () => {
    expect(run(stream({ ShardCount: 1 }))).toHaveLength(1);
    expect(run(stream({ RetentionPeriodHours: 24 }))).toHaveLength(1);
  });

  it('does not flag extended retention or intrinsic values', () => {
    expect(run(stream({ RetentionPeriodHours: 168 }))).toHaveLength(0);
    expect(
      run(stream({ RetentionPeriodHours: { 'Fn::If': ['X', 168, 24] } }))
    ).toHaveLength(0);
  });
});
