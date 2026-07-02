import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { dynamodbPitrDisabled } from './dynamodbPitrDisabled';

describe('dynamodb-pitr-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [dynamodbPitrDisabled]);

  it('flags a table without PITR', () => {
    expect(
      run({
        Resources: {
          Table: { Type: 'AWS::DynamoDB::Table', Properties: {} },
        },
      })
    ).toHaveLength(1);
  });

  it('flags a global table with an uncovered replica', () => {
    expect(
      run({
        Resources: {
          Global: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: {
              Replicas: [
                {
                  Region: 'eu-west-2',
                  PointInTimeRecoverySpecification: {
                    PointInTimeRecoveryEnabled: true,
                  },
                },
                { Region: 'us-east-1' },
              ],
            },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag covered tables and global tables', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: {
              PointInTimeRecoverySpecification: {
                PointInTimeRecoveryEnabled: true,
              },
            },
          },
          Global: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: {
              Replicas: [
                {
                  Region: 'eu-west-2',
                  PointInTimeRecoverySpecification: {
                    PointInTimeRecoveryEnabled: true,
                  },
                },
              ],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
