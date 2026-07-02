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
});
