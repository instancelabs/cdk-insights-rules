import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { stepfunctionsLoggingDisabled } from './stepfunctionsLoggingDisabled';

describe('stepfunctions-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [stepfunctionsLoggingDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: {
        Type: 'AWS::StepFunctions::StateMachine',
        Properties: { RoleArn: 'arn:role', ...properties },
      },
    },
  });

  it('flags missing or OFF logging', () => {
    expect(run(res({}))).toHaveLength(1);
    expect(run(res({ LoggingConfiguration: { Level: 'OFF' } }))).toHaveLength(
      1
    );
  });

  it('does not flag ERROR or ALL levels', () => {
    expect(run(res({ LoggingConfiguration: { Level: 'ERROR' } }))).toHaveLength(
      0
    );
    expect(run(res({ LoggingConfiguration: { Level: 'ALL' } }))).toHaveLength(
      0
    );
  });
});
