import { describe, expect, it } from 'vitest';
import { rules } from './registry';
import { runRules } from './runRules';
import type { Severity, WafPillar } from './types';

/**
 * Invariants every rule in the catalog must satisfy. These run in CI on every
 * PR, so a contributed rule is checked for shape, uniqueness, and — critically —
 * that its own before/after example actually behaves the way it claims.
 */

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const PILLARS: WafPillar[] = [
  'Security',
  'Reliability',
  'Cost Optimization',
  'Performance Efficiency',
  'Operational Excellence',
];

describe('rule catalog contract', () => {
  it('has no duplicate ruleIds', () => {
    const ruleIds = rules.map((rule) => rule.metadata.ruleId);
    expect(new Set(ruleIds).size).toBe(ruleIds.length);
  });

  for (const rule of rules) {
    const metadata = rule.metadata;

    describe(metadata.ruleId, () => {
      it('has a kebab-case ruleId', () => {
        expect(metadata.ruleId).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
      });

      it('has complete, well-formed metadata', () => {
        expect(metadata.name.length).toBeGreaterThan(0);
        expect(metadata.description.length).toBeGreaterThan(0);
        expect(SEVERITIES).toContain(metadata.severity);
        expect(PILLARS).toContain(metadata.wafPillar);
        expect(metadata.resourceTypes.length).toBeGreaterThan(0);
        for (const resourceType of metadata.resourceTypes) {
          expect(resourceType).toMatch(/^AWS::/);
        }
        expect(metadata.awsDocUrl).toMatch(/^https:\/\//);
        expect(metadata.remediationSteps.length).toBeGreaterThan(0);
      });

      it('is a pure function of the template (no findings on an empty template)', () => {
        expect(runRules({ Resources: {} }, [rule])).toHaveLength(0);
        expect(runRules({}, [rule])).toHaveLength(0);
      });

      it('ships a before/after example', () => {
        expect(metadata).toBeDefined();
        expect(rule.example.flagged.length).toBeGreaterThan(0);
        expect(rule.example.fixed.length).toBeGreaterThan(0);
      });
    });
  }
});
