import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { dynamodbEncryptionAwsOwnedKey } from './dynamodbEncryptionAwsOwnedKey';

describe('dynamodb-encryption-aws-owned-key', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [dynamodbEncryptionAwsOwnedKey]);

  const table = (properties: object): CfnTemplate => ({
    Resources: {
      Table: { Type: 'AWS::DynamoDB::Table', Properties: properties },
    },
  });

  it('flags a table without SSESpecification (and global tables)', () => {
    expect(run(table({}))).toHaveLength(1);
    expect(
      run({
        Resources: {
          Global: { Type: 'AWS::DynamoDB::GlobalTable', Properties: {} },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag SSEEnabled true or intrinsic values', () => {
    expect(run(table({ SSESpecification: { SSEEnabled: true } }))).toHaveLength(
      0
    );
    expect(
      run(
        table({
          SSESpecification: { SSEEnabled: { 'Fn::If': ['X', true, false] } },
        })
      )
    ).toHaveLength(0);
  });
});
