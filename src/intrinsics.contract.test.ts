import { describe, expect, it } from 'vitest';
import { rules } from './registry';
import { runRules } from './runRules';
import { synthesizeExample } from './testutil/synthesizeExample';
import type { CfnTemplate } from './types';

/**
 * Behavioral enforcement of the "unknown ≠ violation" doctrine (see cfn.ts):
 * a rule must never report a finding whose deciding value is a CloudFormation
 * intrinsic, because the resolved value can't be known from the template.
 *
 * The deciding properties are derived mechanically from each rule's own
 * example pair: any boolean-ish leaf that differs between the synthesized
 * `flagged` and `fixed` templates is, by the example's own claim, what flips
 * the rule. Replacing those leaves in the `fixed` template with `Fn::If`
 * intrinsics makes them undecidable - and an undecidable template that was
 * previously compliant must produce zero findings.
 *
 * Known limits (covered by per-rule unit tests instead):
 * - Only boolean-ish LEAVES are substituted. A container block that is itself
 *   an intrinsic (`SomeConfig: { 'Fn::If': [...] }`), string/number/array
 *   deciders, and rules whose examples differ by no boolean-ish leaf all pass
 *   this suite vacuously.
 * - Array items are compared by index; an insertion that shifts a decider to
 *   an index where the old value coincidentally matches is not detected.
 */

const UNDECIDABLE = { 'Fn::If': ['IntrinsicsContractCondition', true, false] };

const isBooleanish = (value: unknown): boolean =>
  typeof value === 'boolean' || value === 'true' || value === 'false';

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

/**
 * Paths (as key arrays) of boolean-ish leaves in `fixed` that are absent from
 * or different in `flagged`.
 */
const booleanDiffPaths = (
  fixed: unknown,
  flagged: unknown,
  path: (string | number)[] = []
): (string | number)[][] => {
  if (isBooleanish(fixed)) {
    return fixed === flagged ? [] : [path];
  }
  if (!isPlainObject(fixed)) {
    return [];
  }
  const paths: (string | number)[][] = [];
  for (const [key, value] of Object.entries(fixed)) {
    const counterpart = isPlainObject(flagged)
      ? (flagged as Record<string, unknown>)[key]
      : undefined;
    paths.push(...booleanDiffPaths(value, counterpart, [...path, key]));
  }
  return paths;
};

const setPath = (
  root: Record<string, unknown>,
  path: (string | number)[],
  value: unknown
): void => {
  let cursor: Record<string, unknown> = root;
  for (const key of path.slice(0, -1)) {
    cursor = cursor[key] as Record<string, unknown>;
  }
  cursor[path[path.length - 1]] = value;
};

describe('intrinsics contract: undecidable deciding values never flag', () => {
  for (const rule of rules) {
    it(rule.metadata.ruleId, async () => {
      const flagged = await synthesizeExample(rule.example.flagged);
      const fixed = await synthesizeExample(rule.example.fixed);

      const paths = booleanDiffPaths(fixed.Resources, flagged.Resources);
      if (paths.length === 0) {
        return; // no boolean-ish decider - vacuous for this suite
      }

      const undecidable = structuredClone(fixed) as CfnTemplate;
      for (const path of paths) {
        setPath(
          undecidable.Resources as unknown as Record<string, unknown>,
          path,
          structuredClone(UNDECIDABLE)
        );
      }

      const findings = runRules(undecidable, [rule], {
        onRuleError: (ruleId, error) => {
          throw new Error(`${ruleId} threw on an intrinsic value: ${error}`);
        },
      });
      expect(
        findings,
        `${rule.metadata.ruleId} flagged a value it cannot decide (intrinsic at ${paths
          .map((p) => p.join('.'))
          .join(', ')}) - unknown is not a violation`
      ).toHaveLength(0);
    }, 30_000);
  }
});
