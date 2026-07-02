# cdk-insights-rules

The open catalog of rules that [CDK Insights](https://cdkinsights.dev) runs
against AWS CDK apps — as an installable, testable npm package.

A **rule** is a small pure function that reads a synthesized CloudFormation
template and reports a misconfiguration. That's the whole idea. No CDK, no
network, no filesystem — if you can decide it from the template, you can write a
rule for it, and this README shows you exactly how.

- **[CATALOG.md](CATALOG.md)** — the rules implemented here.
- **[Browse all rules on the site](https://cdkinsights.dev/rules)** — the full
  product catalog, each with a before/after example.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — the contribution workflow.

> **Status:** early. This package open-sources a growing subset of the rules the
> CDK Insights product runs. The scanner itself — CDK synth, source-location
> attribution, the AI analysis tier, and the hosted service — stays in the
> private product. This is the rule engine.

---

## Install

```bash
npm install @instance-labs/cdk-insights-rules
```

**Zero runtime dependencies**, ESM, fully typed. Works with any `aws-cdk-lib`
version — the CDK plugin's types are declared structurally, so nothing is pinned.

## Use it in your CDK app (recommended)

Add the plugin once. Every `cdk synth` then runs the rules against your
synthesized templates — findings show up in CDK's own validation report, and
synth fails if any are found:

```ts
import { App, Validations } from 'aws-cdk-lib';
import { CdkInsightsRulesPlugin } from '@instance-labs/cdk-insights-rules/cdk';

const app = new App();
// ...define your stacks...
Validations.of(app).addPlugins(
  new CdkInsightsRulesPlugin({ minimumSeverity: 'HIGH' }), // threshold is optional
);
```

```
╔════════════════════════════════╗
║   Source: cdk-insights-rules   ║
║   Status: failure              ║
╚════════════════════════════════╝
lambda-url-auth-none (1 occurrences)
Severity: HIGH
  - Construct Path: MyStack/Url
```

Options: `rules` (run a subset — defaults to the full catalog), `minimumSeverity`
(`LOW` | `MEDIUM` | `HIGH` | `CRITICAL`, default `MEDIUM` — `LOW` rules are
advisory nudges, and a validation plugin fails synth, so gate on them only by
explicit opt-in), and `version`.

### Suppressing a finding

Findings you've reviewed and accepted can be acknowledged per resource, so they
stop firing without turning the rule off for everything else:

```ts
const cfnFn = fn.node.defaultChild as lambda.CfnFunction;
cfnFn.addMetadata('cdk-insights', { suppress: ['lambda-tracing-disabled'] });
```

(Or in raw CloudFormation: `Metadata: { "cdk-insights": { "suppress": ["rule-id"] } }`
on the resource.)

## Or use it in your own code / CI

Run the rules against any synthesized CloudFormation template — CDK, SAM, or raw:

```ts
import { runRules } from '@instance-labs/cdk-insights-rules';
import { readFileSync } from 'node:fs';

const template = JSON.parse(readFileSync('cdk.out/MyStack.template.json', 'utf8'));
for (const finding of runRules(template)) {
  console.log(`[${finding.severity}] ${finding.ruleId} on ${finding.resourceId}: ${finding.issue}`);
}
```

```ts
// Cherry-pick: filter the catalog, import individual rules, or mix in your own.
import {
  runRules,
  rules,
  lambdaUrlAuthNone,
  defineRule,
} from '@instance-labs/cdk-insights-rules';

const securityRules = rules.filter((rule) => rule.metadata.wafPillar === 'Security');
runRules(template, [lambdaUrlAuthNone]);
runRules(template, [...securityRules, myOwnRule]);
```

---

## What a rule is

Everything a rule sees is the **synthesized CloudFormation template** — a JSON
object with a `Resources` map. Each resource has a `Type` (like
`AWS::S3::Bucket`) and a `Properties` bag.

A rule walks that map and, for any resource that's misconfigured, calls
`report(...)`. The runner turns each report into a `Finding`, stamping on the
rule's `ruleId`, `severity`, and pillar automatically.

```
template  ──►  rule.check(template, report)  ──►  report(resourceId, {issue, recommendation})  ──►  Finding
```

Two hard requirements:

1. **Pure & deterministic.** A rule may only read the template. No `fetch`, no
   `fs`, no `process`, no `eval`, no imports outside this package. (CI enforces
   this — see [Review](#how-contributions-are-reviewed).)
2. **Low false-positive.** A rule must **not** fire on a valid or default-secure
   configuration. A noisy rule is worse than a missing one, because a user can't
   make a wrong finding go away.

---

## Anatomy of a rule

Here is a complete rule — [`src/rules/lambda/lambdaUrlAuthNone.ts`](src/rules/lambda/lambdaUrlAuthNone.ts),
the reference every other rule follows:

```ts
import type { Rule } from '../../types';

export const lambdaUrlAuthNone: Rule = {
  // 1. METADATA — everything about the rule except its logic.
  metadata: {
    ruleId: 'lambda-url-auth-none',            // unique, kebab-case
    name: 'Lambda Function URL Without Authentication',
    description:
      'Detects Lambda Function URLs configured with AuthType NONE, which allows unauthenticated public invocation.',
    severity: 'HIGH',                          // CRITICAL | HIGH | MEDIUM | LOW
    wafPillar: 'Security',                     // exactly one WA pillar
    resourceTypes: ['AWS::Lambda::Url'],       // the CFN type(s) it inspects
    awsDocUrl: 'https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html',
    remediationSteps: [
      'Set AuthType to AWS_IAM so callers are authorized with IAM SigV4',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'NIST'], // optional
  },

  // 2. CHECK — the detection logic. Pure. Report each violation.
  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(template.Resources ?? {})) {
      if (
        resource.Type === 'AWS::Lambda::Url' &&
        resource.Properties?.AuthType === 'NONE'
      ) {
        report(resourceId, {
          issue:
            'Lambda Function URL uses AuthType NONE, exposing the function to unauthenticated public invocation.',
          recommendation:
            'Set AuthType to AWS_IAM, or front the function with an authenticated API Gateway / CloudFront + WAF.',
        });
      }
    }
  },

  // 3. EXAMPLE — before/after CDK. `flagged` must trip the rule, `fixed` must not.
  example: {
    flagged: `const fn = new lambda.Function(this, 'Fn', { /* ... */ });
fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });`,
    fixed: `const fn = new lambda.Function(this, 'Fn', { /* ... */ });
fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.AWS_IAM });`,
  },
};
```

That's it. Read one property, report one finding. Most rules are ~30 lines.

---

## Build a rule in four steps

1. **Copy the reference.** Duplicate `src/rules/lambda/lambdaUrlAuthNone.ts`
   into `src/rules/<service>/<yourRule>.ts` and rename the export.

2. **Fill in the metadata.** Pick a unique kebab-case `ruleId`, a severity, one
   Well-Architected pillar, the `resourceTypes` you inspect, an AWS docs link,
   and remediation steps.

3. **Write the check.** Walk `template.Resources`, guard every property access
   with `?.`, and `report(resourceId, { issue, recommendation })` on a violation.
   Keep it pure. Use the helpers in [`src/cfn.ts`](src/cfn.ts) — `isIntrinsic`
   (never flag a value you can't decide: `Ref`/`Fn::If` might resolve to the
   safe setting) and `asBoolean` (CloudFormation accepts `"true"` as a boolean).
   (Need a template shape to reason about? Run `cdk synth --json` on a tiny
   stack and look at the JSON.)

4. **Add a test and register it.** Write `<yourRule>.test.ts` next to the rule
   (copy the reference test), add your rule to the array in
   [`src/registry.ts`](src/registry.ts), and export it from
   [`src/index.ts`](src/index.ts) (the contract test fails if you forget).

Then:

```bash
npm run ci        # lint + typecheck + test + security scan — the same gates CI runs
```

The contract tests do a lot of review before a human ever looks:
[`src/rules.contract.test.ts`](src/rules.contract.test.ts) checks your rule for
a unique kebab-case id, complete metadata, that it produces nothing on an empty
template, and that it never mutates its input and is deterministic — and
[`src/examples.contract.test.ts`](src/examples.contract.test.ts) **synthesizes
your before/after example with real `aws-cdk-lib`** and proves `flagged` trips
the rule while `fixed` does not, so examples can never drift from the detection
logic.

---

## The rule contract

Defined in [`src/types.ts`](src/types.ts):

| Type | What it is |
| --- | --- |
| `Rule` | `{ metadata, check, example }` — a complete rule. |
| `RuleMetadata` | `ruleId`, `name`, `description`, `severity`, `wafPillar`, `resourceTypes[]`, `awsDocUrl`, `remediationSteps[]`, `complianceFrameworks?`. |
| `RuleCheck` | `(template, report) => void` — your detection logic. |
| `ReportFinding` | `report(resourceId, { issue, recommendation })` — injected into every check. |
| `CfnTemplate` / `CfnResource` | The template shape. `Properties` is intentionally loose (`any`) — guard with `?.`. |
| `Finding` | What the runner emits: `resourceId`, `ruleId`, `issue`, `recommendation`, `severity`, `wafPillar`. |

`severity`: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`.
`wafPillar`: `Security` · `Reliability` · `Cost Optimization` · `Performance Efficiency` · `Operational Excellence`.

---

## Testing your rule

Tests run the rule against raw template objects — no `cdk synth` needed:

```ts
import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import { lambdaUrlAuthNone } from './lambdaUrlAuthNone';

describe('lambda-url-auth-none', () => {
  const run = (template: object) =>
    runRules(template as never, [lambdaUrlAuthNone]).map((finding) => finding.ruleId);

  it('flags AuthType NONE', () => {
    expect(run({ Resources: { U: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'NONE' } } } }))
      .toContain('lambda-url-auth-none');
  });

  it('does not flag AWS_IAM', () => {
    expect(run({ Resources: { U: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'AWS_IAM' } } } }))
      .toHaveLength(0);
  });
});
```

Cover at least: the violating case (flagged), the compliant case (fixed), and
the tricky "looks bad but is actually fine" case that keeps your false-positive
rate down.

---

## How contributions are reviewed

Every PR that touches a rule runs through layered checks so review is fast and
safe:

1. **Security scan (hard gate).** [`scripts/security-scan.mjs`](scripts/security-scan.mjs)
   statically rejects anything a pure rule has no business doing — `eval`,
   `require`/dynamic `import`, `child_process`, `fs`, `process`, `fetch`,
   node builtins, constructor/`Reflect` escapes, obfuscated strings, or
   importing anything outside this package. A rule literally cannot merge with
   those in it. (The scan covers `src/rules/**` — the contributed surface;
   changes to the engine or scripts get stricter human review instead.)
2. **Typecheck + tests (hard gate).** The contract tests validate your rule's
   shape, purity, and — by synthesizing them with real `aws-cdk-lib` — that its
   before/after example matches its detection logic; your own tests validate
   its behaviour.
3. **AI review (advisory, maintainer-triggered).** When a maintainer applies
   the `ai-review` label, [`scripts/ai-review.mjs`](scripts/ai-review.mjs)
   sends the diff to Claude and posts a structured review — correctness,
   false-positive risk, integration fit, and any security concerns — as a PR
   comment, giving a maintainer a fast first read.
4. **Human review.** A maintainer makes the final call. A rule is a
   false-positive for *every* user, so new detection logic always gets a human.

The AI reviewer only ever reads the diff as data — it never executes contributed
code, and the security scan runs before anything else. Because the diff it reads
is untrusted text, its verdict is treated as untrusted too: the model's output
is validated against strict enums and fully escaped before being rendered, the
model is asked to flag suspected prompt-injection attempts, and a clean AI
review never substitutes for the human one.

---

## Layout

```
src/
  types.ts            The rule contract.
  cfn.ts              Shared template-reading helpers (intrinsics, booleans).
  runRules.ts         The engine: template -> findings (+ suppressions, onRuleError).
  registry.ts         The list of all rules.
  defineRule.ts       Authoring helper.
  rules/<service>/    One file per rule (+ a co-located test).
  cdk/                The CDK policy-validation plugin (the "./cdk" entry point).
  examples.contract.test.ts  Synthesizes every rule's example and proves it.
scripts/
  security-scan.mjs   Static safety gate for rule files.
  ai-review.mjs       AI-assisted PR review.
  build-catalog.mjs   Regenerates CATALOG.md from the built rules.
catalog/
  product-catalog.json  Reference: the full product rule set (all 119).
```

---

## License

[Apache-2.0](LICENSE). Free to read, run, and build on.
