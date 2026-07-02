import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { eventbridgeBusPolicyWildcardPrincipal } from './eventbridgeBusPolicyWildcardPrincipal';

const busPolicy = (properties: object): CfnTemplate => ({
  Resources: {
    Policy: {
      Type: 'AWS::Events::EventBusPolicy',
      Properties: { StatementId: 'sid', ...properties },
    },
  },
});

describe('eventbridge-bus-policy-wildcard-principal', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [eventbridgeBusPolicyWildcardPrincipal]);

  it('flags a legacy-form wildcard principal with no condition', () => {
    expect(
      run(busPolicy({ Action: 'events:PutEvents', Principal: '*' }))
    ).toHaveLength(1);
  });

  it('flags a Statement-form wildcard principal', () => {
    expect(
      run(
        busPolicy({
          Statement: {
            Effect: 'Allow',
            Principal: '*',
            Action: 'events:PutEvents',
            Resource: 'arn:aws:events:eu-west-2:1:event-bus/default',
          },
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag a wildcard scoped by a condition (legacy org form)', () => {
    expect(
      run(
        busPolicy({
          Action: 'events:PutEvents',
          Principal: '*',
          Condition: {
            Type: 'StringEquals',
            Key: 'aws:PrincipalOrgID',
            Value: 'o-abc',
          },
        })
      )
    ).toHaveLength(0);
  });

  it('does not flag a specific account principal', () => {
    expect(
      run(busPolicy({ Action: 'events:PutEvents', Principal: '111122223333' }))
    ).toHaveLength(0);
  });
});
