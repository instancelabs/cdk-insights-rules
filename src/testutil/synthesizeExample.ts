import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import type { CfnTemplate } from '../types';

/**
 * Test-only helper (excluded from the published build): synthesize a rule's
 * example snippet into a CloudFormation template with the real aws-cdk-lib.
 *
 * Snippets are trusted first-party code (they live in this repo and go through
 * the same review as the rule), so executing them here is no different from
 * executing the rule's own test file.
 */

const IMPORT_LINE = /^import \* as (\w+) from '([^']+)';$/;

export const synthesizeExample = async (
  snippet: string
): Promise<CfnTemplate> => {
  const aliases: string[] = [];
  const modules: unknown[] = [];
  const body: string[] = [];

  for (const line of snippet.split('\n')) {
    if (line.startsWith('import')) {
      const match = line.match(IMPORT_LINE);
      if (!match) {
        throw new Error(
          `Example imports must have the form "import * as x from 'aws-cdk-lib/...';" - got: ${line}`
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
