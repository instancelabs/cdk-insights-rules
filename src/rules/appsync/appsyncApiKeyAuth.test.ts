import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { appsyncApiKeyAuth } from './appsyncApiKeyAuth';

describe('appsync-api-key-auth', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [appsyncApiKeyAuth]);

  const api = (authenticationType: string): CfnTemplate => ({
    Resources: {
      Api: {
        Type: 'AWS::AppSync::GraphQLApi',
        Properties: { Name: 'api', AuthenticationType: authenticationType },
      },
    },
  });

  it('flags API_KEY as the primary auth', () => {
    expect(run(api('API_KEY'))).toHaveLength(1);
  });

  it('does not flag IAM or Cognito auth', () => {
    expect(run(api('AWS_IAM'))).toHaveLength(0);
    expect(run(api('AMAZON_COGNITO_USER_POOLS'))).toHaveLength(0);
  });
});
