import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { dynamodbAutoscalingMissing } from './dynamodbAutoscalingMissing';

describe('dynamodb-autoscaling-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [dynamodbAutoscalingMissing]);

  const provisionedTable = {
    Type: 'AWS::DynamoDB::Table',
    Properties: {
      ProvisionedThroughput: { ReadCapacityUnits: 50, WriteCapacityUnits: 50 },
    },
  };

  it('flags a provisioned table with no scaling target', () => {
    expect(run({ Resources: { Table: provisionedTable } })).toHaveLength(1);
  });

  it('does not flag on-demand tables or scaled tables', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: { BillingMode: 'PAY_PER_REQUEST' },
          },
        },
      })
    ).toHaveLength(0);
    expect(
      run({
        Resources: {
          Table: provisionedTable,
          Target: {
            Type: 'AWS::ApplicationAutoScaling::ScalableTarget',
            Properties: {
              ScalableDimension: 'dynamodb:table:ReadCapacityUnits',
              ResourceId: {
                'Fn::Sub': ['table/${T}', { T: { Ref: 'Table' } }],
              },
              ServiceNamespace: 'dynamodb',
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
