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

  it('accepts the CloudFormation string form "true"', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: {
              PointInTimeRecoverySpecification: {
                PointInTimeRecoveryEnabled: 'true',
              },
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('skips intrinsic values instead of flagging them', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: {
              PointInTimeRecoverySpecification: {
                PointInTimeRecoveryEnabled: {
                  'Fn::If': ['IsProd', true, false],
                },
              },
            },
          },
          WholeSpec: {
            Type: 'AWS::DynamoDB::Table',
            Properties: {
              PointInTimeRecoverySpecification: { Ref: 'SpecParam' },
            },
          },
          Global: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: {
              Replicas: [
                {
                  Region: 'eu-west-2',
                  PointInTimeRecoverySpecification: {
                    PointInTimeRecoveryEnabled: { Ref: 'PitrParam' },
                  },
                },
              ],
            },
          },
        },
      })
    ).toHaveLength(0);
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

  it('skips an intrinsic replica entry but flags a decidably missing replica list', () => {
    expect(
      run({
        Resources: {
          Global: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: {
              Replicas: [
                {
                  'Fn::If': [
                    'IsProd',
                    { Region: 'us-east-1' },
                    { Ref: 'AWS::NoValue' },
                  ],
                },
              ],
            },
          },
          IntrinsicList: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: { Replicas: { 'Fn::If': ['A', [], []] } },
          },
        },
      })
    ).toHaveLength(0);
    expect(
      run({
        Resources: {
          Global: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: {},
          },
        },
      })
    ).toHaveLength(1);
  });
});
