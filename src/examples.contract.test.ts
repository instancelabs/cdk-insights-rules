import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { describe, expect, it } from 'vitest';
import { rules } from './registry';
import { runRules } from './runRules';
import type { CfnTemplate, Rule } from './types';

/**
 * The guarantee behind every rule's before/after example: `flagged` MUST trip
 * the rule and `fixed` MUST NOT. This suite enforces it by actually running
 * each snippet — the code is executed inside a real CDK stack, synthesized
 * with aws-cdk-lib, and the resulting template is fed to the rule. An example
 * that drifts from the detection logic fails CI.
 *
 * Snippets are trusted first-party code (they live in this repo and go through
 * the same review as the rule), so executing them here is no different from
 * executing the rule's own test file.
 */

const IMPORT_LINE = /^import \* as (\w+) from '([^']+)';$/;

/** Synthesize an example snippet into a CloudFormation template. */
const synthesizeExample = async (snippet: string): Promise<CfnTemplate> => {
  const aliases: string[] = [];
  const modules: unknown[] = [];
  const body: string[] = [];

  for (const line of snippet.split('\n')) {
    if (line.startsWith('import')) {
      const match = line.match(IMPORT_LINE);
      if (!match) {
        throw new Error(
          `Example imports must have the form "import * as x from 'aws-cdk-lib/...';" — got: ${line}`
        );
      }
      aliases.push(match[1]);
      modules.push(await import(match[2]));
    } else {
      body.push(line);
    }
  }

  const app = new App();
  const stack = new Stack(app, 'Example');
  // The snippet is written as CDK construct code with `this` as the scope
  // (exactly how it appears in a Stack constructor). Function() gives us a
  // non-strict function whose `this` we can bind to the stack.
  const construct = new Function(...aliases, body.join('\n'));
  construct.call(stack, ...modules);

  return Template.fromStack(stack).toJSON() as CfnTemplate;
};

const findingsOf = async (rule: Rule, snippet: string) =>
  runRules(await synthesizeExample(snippet), [rule], {
    onRuleError: (ruleId, error) => {
      throw new Error(`${ruleId} threw on its own example: ${error}`);
    },
  });

describe('example contract: flagged trips the rule, fixed does not', () => {
  for (const rule of rules) {
    describe(rule.metadata.ruleId, () => {
      it('example.flagged trips the rule', async () => {
        const findings = await findingsOf(rule, rule.example.flagged);
        expect(findings.length).toBeGreaterThan(0);
      });

      it('example.fixed does not trip the rule', async () => {
        const findings = await findingsOf(rule, rule.example.fixed);
        expect(findings).toHaveLength(0);
      });
    });
  }
});
