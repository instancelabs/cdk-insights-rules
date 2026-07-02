import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { dynamodbDeletionProtectionDisabled } from './dynamodbDeletionProtectionDisabled';

describe('dynamodb-deletion-protection-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [dynamodbDeletionProtectionDisabled]).map(
      (finding) => finding.ruleId
    );

  it('flags a table with no deletion protection', () => {
    expect(
      run({
        Resources: {
          Table: { Type: 'AWS::DynamoDB::Table', Properties: {} },
        },
      })
    ).toContain('dynamodb-deletion-protection-disabled');
  });

  it('flags a table with DeletionProtectionEnabled false', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: { DeletionProtectionEnabled: false },
          },
        },
      })
    ).toContain('dynamodb-deletion-protection-disabled');
  });

  it('does not flag a table with DeletionProtectionEnabled true', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: { DeletionProtectionEnabled: true },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag the CloudFormation string form "true"', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: { DeletionProtectionEnabled: 'true' },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('does not flag a value set via an intrinsic (undecidable)', () => {
    expect(
      run({
        Resources: {
          Table: {
            Type: 'AWS::DynamoDB::Table',
            Properties: {
              DeletionProtectionEnabled: { 'Fn::If': ['IsProd', true, false] },
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('flags a global table with an unprotected replica', () => {
    expect(
      run({
        Resources: {
          Global: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: {
              Replicas: [
                { Region: 'eu-west-2', DeletionProtectionEnabled: true },
                { Region: 'us-east-1' },
              ],
            },
          },
        },
      })
    ).toContain('dynamodb-deletion-protection-disabled');
  });

  it('does not flag a global table whose replicas are all protected', () => {
    expect(
      run({
        Resources: {
          Global: {
            Type: 'AWS::DynamoDB::GlobalTable',
            Properties: {
              Replicas: [
                { Region: 'eu-west-2', DeletionProtectionEnabled: true },
                { Region: 'us-east-1', DeletionProtectionEnabled: true },
              ],
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
