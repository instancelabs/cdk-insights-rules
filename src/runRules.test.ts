import { describe, expect, it, vi } from 'vitest';
import { defineRule } from './defineRule';
import { lambdaUrlAuthNone } from './rules/lambda/lambdaUrlAuthNone';
import { runRules } from './runRules';

const flaggedTemplate = {
  Resources: {
    Url: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'NONE' } },
  },
};

describe('runRules', () => {
  it('reports a rule that throws via onRuleError and keeps running the rest', () => {
    const throwingRule = defineRule({
      metadata: { ...lambdaUrlAuthNone.metadata, ruleId: 'always-throws' },
      check: () => {
        throw new Error('boom');
      },
      example: lambdaUrlAuthNone.example,
    });

    const onRuleError = vi.fn();
    const findings = runRules(
      flaggedTemplate,
      [throwingRule, lambdaUrlAuthNone],
      { onRuleError }
    );

    expect(onRuleError).toHaveBeenCalledWith(
      'always-throws',
      expect.any(Error)
    );
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'lambda-url-auth-none',
    ]);
  });

  it('warns on the console by default when a rule throws', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const throwingRule = defineRule({
      metadata: { ...lambdaUrlAuthNone.metadata, ruleId: 'always-throws' },
      check: () => {
        throw new Error('boom');
      },
      example: lambdaUrlAuthNone.example,
    });

    runRules({ Resources: {} }, [throwingRule]);

    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toContain('always-throws');
    warn.mockRestore();
  });

  it('drops findings suppressed via resource metadata', () => {
    const findings = runRules(
      {
        Resources: {
          Url: {
            Type: 'AWS::Lambda::Url',
            Properties: { AuthType: 'NONE' },
            Metadata: {
              'cdk-insights': { suppress: ['lambda-url-auth-none'] },
            },
          },
        },
      },
      [lambdaUrlAuthNone]
    );

    expect(findings).toHaveLength(0);
  });

  it('does not drop findings for other rule ids in a suppress list', () => {
    const findings = runRules(
      {
        Resources: {
          Url: {
            Type: 'AWS::Lambda::Url',
            Properties: { AuthType: 'NONE' },
            Metadata: { 'cdk-insights': { suppress: ['some-other-rule'] } },
          },
        },
      },
      [lambdaUrlAuthNone]
    );

    expect(findings).toHaveLength(1);
  });
});
