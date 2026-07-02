import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { cloudtrailLoggingDisabled } from './cloudtrailLoggingDisabled';

const trail = (properties: object): CfnTemplate => ({
  Resources: {
    Trail: { Type: 'AWS::CloudTrail::Trail', Properties: properties },
  },
});

describe('cloudtrail-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [cloudtrailLoggingDisabled]);

  it('flags a trail with IsLogging false (boolean or string form)', () => {
    expect(run(trail({ IsLogging: false }))).toHaveLength(1);
    expect(run(trail({ IsLogging: 'false' }))).toHaveLength(1);
  });

  it('does not flag a logging trail or an intrinsic value', () => {
    expect(run(trail({ IsLogging: true }))).toHaveLength(0);
    expect(
      run(trail({ IsLogging: { 'Fn::If': ['X', true, false] } }))
    ).toHaveLength(0);
  });
});
