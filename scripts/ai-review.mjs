#!/usr/bin/env node
/**
 * AI-assisted review of a rule contribution.
 *
 * Reads a unified diff (a PR's changes) and asks Claude to evaluate the
 * proposed rule the way a maintainer would: does it fit the rule contract, is
 * the detection logic correct, what's the false-positive risk, and — most
 * importantly — is there anything suspicious in it. The result is posted as a
 * PR comment and written to the job summary.
 *
 * This is ADVISORY. The hard gates are `security-scan`, `typecheck`, and the
 * test suite (which validate mechanically). This gives a human reviewer a fast,
 * structured first read.
 *
 * Safety: this script only ever treats the diff as DATA sent to the model. It
 * never executes the contributed code. The workflow that runs it (which holds
 * the API key) checks out the trusted base branch, not the PR head.
 *
 * Input:  the diff on stdin, or a path as argv[2].
 * Env:    ANTHROPIC_API_KEY (required to call the model; absent => skip, exit 0)
 *         ANTHROPIC_MODEL   (default: claude-sonnet-4-6)
 *         GITHUB_STEP_SUMMARY (optional: markdown summary target)
 */
import { appendFileSync, readFileSync } from 'node:fs';

const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6';
const API_KEY = process.env.ANTHROPIC_API_KEY;

const readInput = () => {
  const path = process.argv[2];
  if (path) return readFileSync(path, 'utf8');
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
};

const CONTRACT = `A CDK Insights rule is a PURE function over a synthesized CloudFormation template.
Shape: an exported \`Rule\` object with:
- metadata: { ruleId (kebab-case, unique), name, description, severity (CRITICAL|HIGH|MEDIUM|LOW), wafPillar (one Well-Architected pillar), resourceTypes[], awsDocUrl, remediationSteps[], complianceFrameworks? }
- check(template, report): iterates template.Resources and calls report(resourceId, { issue, recommendation }) for violations. No I/O, network, fs, process, eval, or dynamic imports.
- example: { flagged, fixed } CDK snippets — flagged MUST trip the rule, fixed MUST NOT.
The project optimises for TRUST: a rule must NOT fire on a valid or default-secure config (false positives are worse than gaps).`;

const PROMPT = (
  diff
) => `You are reviewing a pull request to the open CDK Insights rule catalog.

${CONTRACT}

Evaluate the change below. Focus on:
1. security — anything malicious, obfuscated, or that reaches outside a pure template check (highest priority)
2. correctness — does the check actually detect what the metadata claims?
3. false-positive risk — could it fire on a valid/default-secure config?
4. integration fit — does it follow the contract shape, unique kebab-case ruleId, complete metadata, a test, and a before/after example?

Respond with ONLY a JSON object, no prose, matching:
{
  "verdict": "approve" | "request-changes" | "reject",
  "score": <0-100 integer>,
  "security_concerns": [<string>, ...],
  "correctness": <string>,
  "false_positive_risk": "low" | "medium" | "high",
  "integration_fit": <string>,
  "suggestions": [<string>, ...],
  "summary": <string, one or two sentences>
}

--- BEGIN DIFF ---
${diff.slice(0, 60000)}
--- END DIFF ---`;

const writeSummary = (markdown) => {
  console.log(markdown);
  const summaryTarget = process.env.GITHUB_STEP_SUMMARY;
  if (summaryTarget) {
    try {
      appendFileSync(summaryTarget, `${markdown}\n`);
    } catch {
      // best-effort; stdout already has it
    }
  }
};

const renderMarkdown = (review) => {
  const verdictEmoji =
    review.verdict === 'approve'
      ? '✅'
      : review.verdict === 'reject'
        ? '⛔'
        : '⚠️';
  const lines = [
    '## 🤖 Automated rule review',
    '',
    `**Verdict:** ${verdictEmoji} \`${review.verdict}\` &nbsp;·&nbsp; **Score:** ${review.score}/100 &nbsp;·&nbsp; **False-positive risk:** ${review.false_positive_risk}`,
    '',
    `${review.summary}`,
    '',
    `**Correctness:** ${review.correctness}`,
    '',
    `**Integration fit:** ${review.integration_fit}`,
  ];
  if (review.security_concerns?.length) {
    lines.push('', '**⚠️ Security concerns:**');
    for (const concern of review.security_concerns) {
      lines.push(`- ${concern}`);
    }
  } else {
    lines.push('', '**Security:** no concerns flagged.');
  }
  if (review.suggestions?.length) {
    lines.push('', '**Suggestions:**');
    for (const suggestion of review.suggestions) {
      lines.push(`- ${suggestion}`);
    }
  }
  lines.push(
    '',
    '<sub>Advisory only — the hard gates are the security scan, typecheck, and test suite. A human maintainer makes the call.</sub>'
  );
  return lines.join('\n');
};

const main = async () => {
  const diff = readInput().trim();
  if (!diff) {
    writeSummary('_No rule changes to review._');
    return;
  }
  if (!API_KEY) {
    writeSummary(
      '_AI review skipped: `ANTHROPIC_API_KEY` not available (expected on fork PRs). Human review still applies._'
    );
    return;
  }

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 1024,
      messages: [{ role: 'user', content: PROMPT(diff) }],
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    writeSummary(
      `_AI review unavailable (API ${response.status})._\n\n${body.slice(0, 500)}`
    );
    return;
  }

  const data = await response.json();
  const text = data?.content?.[0]?.text ?? '';
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    writeSummary(
      `_AI review returned no parseable verdict._\n\n${text.slice(0, 800)}`
    );
    return;
  }

  let review;
  try {
    review = JSON.parse(jsonMatch[0]);
  } catch {
    writeSummary(
      `_AI review returned malformed JSON._\n\n${text.slice(0, 800)}`
    );
    return;
  }

  writeSummary(renderMarkdown(review));
};

main().catch((err) => {
  writeSummary(`_AI review errored: ${err?.message ?? err}_`);
});
