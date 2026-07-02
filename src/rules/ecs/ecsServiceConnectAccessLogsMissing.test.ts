import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecsServiceConnectAccessLogsMissing } from './ecsServiceConnectAccessLogsMissing';

describe('ecs-service-connect-access-logs-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecsServiceConnectAccessLogsMissing]);

  const service = (serviceConnect?: object): CfnTemplate => ({
    Resources: {
      Service: {
        Type: 'AWS::ECS::Service',
        Properties: serviceConnect
          ? { ServiceConnectConfiguration: serviceConnect }
          : {},
      },
    },
  });

  it('flags Service Connect enabled without log configuration', () => {
    expect(run(service({ Enabled: true }))).toHaveLength(1);
  });

  it('does not flag a log driver, disabled Service Connect, or absence', () => {
    expect(
      run(
        service({ Enabled: true, LogConfiguration: { LogDriver: 'awslogs' } })
      )
    ).toHaveLength(0);
    expect(run(service({ Enabled: false }))).toHaveLength(0);
    expect(run(service())).toHaveLength(0);
  });
});
