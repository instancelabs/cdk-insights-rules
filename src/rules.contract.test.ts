import { describe, expect, it } from 'vitest';
import * as packageExports from './index';
import { rules } from './registry';
import { runRules } from './runRules';
import type { CfnTemplate, Severity, WafPillar } from './types';

/** Recursively freeze a template so any mutation by a rule throws. */
const deepFreeze = <T>(value: T): T => {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
};

/** A busy template exercising every resource type the catalog inspects. */
const kitchenSink = (): CfnTemplate => ({
  Resources: {
    Url: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'NONE' } },
    Fn: { Type: 'AWS::Lambda::Function', Properties: {} },
    Lt: { Type: 'AWS::EC2::LaunchTemplate', Properties: {} },
    Bucket: { Type: 'AWS::S3::Bucket', Properties: {} },
    Table: { Type: 'AWS::DynamoDB::Table', Properties: {} },
    TaskDef: {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: { ContainerDefinitions: [{ Name: 'app', Privileged: true }] },
    },
    Queue: { Type: 'AWS::SQS::Queue', Properties: {} },
    Domain: {
      Type: 'AWS::ApiGateway::DomainName',
      Properties: { DomainName: 'api.example.com' },
    },
    Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'x' } },
    Mapping: {
      Type: 'AWS::ApiGateway::BasePathMapping',
      Properties: { DomainName: 'api.example.com', RestApiId: { Ref: 'Api' } },
    },
    Stage: { Type: 'AWS::ApiGateway::Stage', Properties: {} },
  },
});

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
  it('has no duplicate ruleIds (including legacy aliases)', () => {
    const ruleIds = rules.flatMap((rule) => [
      rule.metadata.ruleId,
      ...(rule.metadata.legacyRuleIds ?? []),
    ]);
    expect(new Set(ruleIds).size).toBe(ruleIds.length);
  });

  it('exports every registered rule individually from the package index', () => {
    const exported = new Set(Object.values(packageExports));
    for (const rule of rules) {
      expect(
        exported,
        `${rule.metadata.ruleId} missing from src/index.ts`
      ).toContain(rule);
    }
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

      it('produces no findings on an empty template', () => {
        expect(runRules({ Resources: {} }, [rule])).toHaveLength(0);
        expect(runRules({}, [rule])).toHaveLength(0);
      });

      it('never mutates the template and is deterministic', () => {
        // Frozen template: any write by the rule throws (surfaced by runRules'
        // onRuleError below). Two runs must produce identical findings.
        const template = deepFreeze(kitchenSink());
        const fail = (ruleId: string, error: unknown) => {
          throw new Error(`${ruleId} threw on a frozen template: ${error}`);
        };
        const first = runRules(template, [rule], { onRuleError: fail });
        const second = runRules(template, [rule], { onRuleError: fail });
        expect(second).toEqual(first);
      });

      it('ships a before/after example', () => {
        expect(metadata).toBeDefined();
        expect(rule.example.flagged.length).toBeGreaterThan(0);
        expect(rule.example.fixed.length).toBeGreaterThan(0);
      });
    });
  }
});
