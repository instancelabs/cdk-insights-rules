import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { rdsEnhancedMonitoringDisabled } from './rdsEnhancedMonitoringDisabled';

describe('rds-enhanced-monitoring-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [rdsEnhancedMonitoringDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::RDS::DBInstance', Properties: { ...properties } },
    },
  });

  it('flags missing or zero monitoring intervals', () => {
    expect(run(res({}))).toHaveLength(1);
    expect(run(res({ MonitoringInterval: 0 }))).toHaveLength(1);
  });

  it('does not flag valid intervals (number or string) or intrinsics', () => {
    expect(run(res({ MonitoringInterval: 60 }))).toHaveLength(0);
    expect(run(res({ MonitoringInterval: '30' }))).toHaveLength(0);
    expect(
      run(res({ MonitoringInterval: { 'Fn::If': ['X', 60, 0] } }))
    ).toHaveLength(0);
  });
});
