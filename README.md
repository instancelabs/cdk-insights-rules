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

## Install & use

```bash
npm install cdk-insights-rules
```

```ts
import { runRules } from 'cdk-insights-rules';
import { readFileSync } from 'node:fs';

// Feed it a synthesized template (e.g. from `cdk synth --json`, or a
// cdk.out/*.template.json file).
const template = JSON.parse(readFileSync('cdk.out/MyStack.template.json', 'utf8'));

const findings = runRules(template);
for (const finding of findings) {
  console.log(`[${finding.severity}] ${finding.ruleId} on ${finding.resourceId}: ${finding.issue}`);
}
```

```ts
// Or run a single rule / your own selection:
import { runRules, rules } from 'cdk-insights-rules';

const securityRules = rules.filter((rule) => rule.metadata.wafPillar === 'Security');
const findings = runRules(template, securityRules);
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
   Keep it pure. (Need a template shape to reason about? Run `cdk synth --json`
   on a tiny stack and look at the JSON.)

4. **Add a test and register it.** Write `<yourRule>.test.ts` next to the rule
   (copy the reference test), then add your rule to the array in
   [`src/registry.ts`](src/registry.ts).

Then:

```bash
npm run ci        # lint + typecheck + test + security scan — the same gates CI runs
```

The contract test ([`src/rules.contract.test.ts`](src/rules.contract.test.ts))
automatically checks your rule for a unique kebab-case id, complete metadata, and
that it produces nothing on an empty template — so a lot of review is done for
you before a human ever looks.

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
   node builtins, obfuscated strings, or importing anything outside this
   package. A rule literally cannot merge with those in it.
2. **Typecheck + tests (hard gate).** The contract test validates your rule's
   shape; your own tests validate its behaviour.
3. **AI review (advisory).** [`scripts/ai-review.mjs`](scripts/ai-review.mjs)
   sends the diff to Claude and posts a structured review — correctness,
   false-positive risk, integration fit, and any security concerns — as a PR
   comment, giving a maintainer a fast first read.
4. **Human review.** A maintainer makes the final call. A rule is a
   false-positive for *every* user, so new detection logic always gets a human.

The AI reviewer only ever reads the diff as data — it never executes contributed
code, and the security scan runs before anything else.

---

## Layout

```
src/
  types.ts            The rule contract.
  runRules.ts         The engine: template -> findings.
  registry.ts         The list of all rules.
  rules/<service>/    One file per rule (+ a co-located test).
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
