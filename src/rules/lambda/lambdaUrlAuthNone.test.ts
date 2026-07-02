import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaUrlAuthNone } from './lambdaUrlAuthNone';

describe('lambda-url-auth-none', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaUrlAuthNone]).map((finding) => finding.ruleId);

  it('flags a Function URL with AuthType NONE', () => {
    expect(
      run({
        Resources: {
          Url: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'NONE' } },
        },
      })
    ).toContain('lambda-url-auth-none');
  });

  it('does not flag a Function URL with AuthType AWS_IAM', () => {
    expect(
      run({
        Resources: {
          Url: {
            Type: 'AWS::Lambda::Url',
            Properties: { AuthType: 'AWS_IAM' },
          },
        },
      })
    ).toHaveLength(0);
  });
});
