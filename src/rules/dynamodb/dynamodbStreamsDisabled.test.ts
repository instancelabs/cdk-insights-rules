import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { dynamodbStreamsDisabled } from './dynamodbStreamsDisabled';

describe('dynamodb-streams-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [dynamodbStreamsDisabled]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::DynamoDB::Table', Properties: { ...properties } },
    },
  });

  it('flags a table without streams', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('does not flag streams enabled', () => {
    expect(
      run(
        res({ StreamSpecification: { StreamViewType: 'NEW_AND_OLD_IMAGES' } })
      )
    ).toHaveLength(0);
  });
});
