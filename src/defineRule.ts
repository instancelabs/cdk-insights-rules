import type { Rule } from './types.js';

/**
 * Identity helper for authoring a rule. Purely for DX: it gives you full
 * type-checking and autocompletion on the object literal without having to
 * write `const myRule: Rule = { ... }`.
 *
 *   export const myRule = defineRule({ metadata: { ... }, check: ..., example: ... });
 */
export const defineRule = (rule: Rule): Rule => rule;
