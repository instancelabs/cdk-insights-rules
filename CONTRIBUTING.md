# Contributing

Thanks for helping CDK Insights catch more real problems. There are two ways in:

- **Propose a rule** — an idea, no code. Open a
  [rule proposal issue](https://github.com/instancelabs/cdk-insights-rules/issues/new?template=propose-a-rule.yml).
- **Contribute a rule** — the code. A check function, a test, and a registry
  entry. Read on.

The full walkthrough (anatomy, the four steps, the contract) is in the
[README](README.md#build-a-rule-in-four-steps). This file is the reviewer-facing
checklist and the bar a rule has to clear.

## The bar for a good rule

CDK Insights optimises for **trust**. A rule that fires on a secure or default
configuration is worse than a missing rule. So every rule must be:

- **Deterministic** — decidable from the synthesized template alone.
- **Low false-positive** — it must not fire on a valid or default-secure config.
  If a "bad" pattern is sometimes legitimate, scope the rule tightly or drop the
  severity to advisory (LOW). Never flag a value you cannot decide: intrinsics
  (`Ref`, `Fn::If`, ...) may resolve to the safe setting, and CloudFormation
  accepts `"true"` as a boolean — use `isIntrinsic` / `asBoolean` from
  [`src/cfn.ts`](src/cfn.ts).
- **Actionable** — the fix is a specific property change the user controls.
- **Pure** — no network, filesystem, process, `eval`, dynamic imports, or any
  import outside this package. This is enforced mechanically (see below).
- **Mapped** — exactly one Well-Architected pillar.

## Submitting a rule (checklist)

1. `src/rules/<service>/<yourRule>.ts` exports a `Rule` (copy the reference,
   `src/rules/lambda/lambdaUrlAuthNone.ts`).
2. A co-located `<yourRule>.test.ts` covers: the violating case, the compliant
   case, and the "looks bad but is fine" edge case.
3. The rule is added to the array in `src/registry.ts` **and** exported from
   `src/index.ts` (the contract test fails if either is missing).
4. `ruleId` is unique and kebab-case; metadata is complete; `example.flagged`
   trips the rule and `example.fixed` does not — CI proves this by actually
   synthesizing both snippets with `aws-cdk-lib` and running your rule on the
   output (`src/examples.contract.test.ts`).
5. `npm run ci` passes locally (lint + typecheck + test + security scan).

One rule per PR — it's easier to review and validate.

## How your PR is checked

| Gate | What it does | Blocking? |
| --- | --- | --- |
| `security-scan` | Rejects `eval`, `require`, dynamic `import`, `child_process`, `fs`, `process`, `fetch`, node builtins, constructor/`Reflect` escapes, obfuscation, or non-package imports in rule files (`src/rules/**` — anything outside that surface gets stricter human review instead). | **Yes** |
| `typecheck` + tests | Contract tests validate shape/uniqueness/purity and synthesize your before/after example to prove it matches the detection logic; your tests validate behaviour. | **Yes** |
| AI review | When a maintainer applies the `ai-review` label, Claude posts a structured review (correctness, false-positive risk, integration fit, security) as a PR comment. Its output is schema-validated and escaped before rendering, and it flags suspected prompt-injection attempts. | No (advisory) |
| Maintainer review | A human makes the final call — every new rule gets one. The AI review is treated as untrusted input: it can raise concerns worth chasing, but a clean AI review never shortcuts human review. | **Yes** |

## What a good proposal looks like

If you're proposing rather than coding, answer these (the issue template asks
for them):

1. **Resource type(s)** — e.g. `AWS::Lambda::Url`.
2. **The condition** — the exact property gap, e.g. `Properties.AuthType === 'NONE'`.
3. **Why it matters** — the concrete risk, with an AWS docs link.
4. **Severity + pillar** — with a one-line justification.
5. **A before/after CDK snippet** — the single most useful thing you can include.
6. **False-positive edge cases** — when is the pattern legitimate, and how does
   the rule avoid flagging it?

## Ground rules

- Link the AWS documentation for the control.
- Be honest about false positives; a scoped-down rule beats a broad noisy one.
- **Conventional commits** are enforced (a commitlint hook checks every message):
  `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `security:`, etc.
  A pre-commit hook runs lint + typecheck. Run `npm install` once to enable them.
- By contributing you agree your contribution is licensed under
  [Apache-2.0](LICENSE).

## Releasing (maintainers)

Publishing is version-gated on push to `main` (like the `cdk-insights` CLI): a
merge publishes only when `package.json`'s version changed. Cut a release with
`npm run release:patch` | `release:minor` | `release:major` (bumps the version
and regenerates `CHANGELOG.md` from the conventional commits), or bump manually.
