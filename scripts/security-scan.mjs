#!/usr/bin/env node
/**
 * Static safety gate for rule files.
 *
 * A rule is a PURE function over a CloudFormation template. It must never touch
 * the network, the filesystem, the process, or the module system. This script
 * enforces that mechanically so a contributed (or compromised) rule can't run
 * arbitrary code in CI, in the package, or in a consumer's build.
 *
 * It is defence-in-depth, not a substitute for human review — but it makes the
 * common malicious patterns impossible to merge by accident.
 *
 * SCOPE: only `src/rules/**` is scanned — that is the surface contributors
 * touch. Changes to the engine (`src/*.ts`), the CDK plugin, `scripts/`, or
 * the workflows are NOT covered by this gate and get correspondingly stricter
 * human review.
 *
 * Usage:
 *   node scripts/security-scan.mjs                 # scan all rule files
 *   node scripts/security-scan.mjs a.ts b.ts       # scan specific files
 *
 * Exits non-zero if any file violates the rules.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const projectRoot = process.cwd();
const rulesDir = join(projectRoot, 'src', 'rules');

// Bare (non-relative) imports allowed, by file kind. Rule implementations may
// import nothing external; test files may import the test runner only.
const allowedBareImportsInTests = new Set(['vitest']);

// Patterns that have no business in a pure template check. Each is a hard fail.
const forbiddenConstructs = [
  { pattern: /\beval\s*\(/, label: 'eval()' },
  { pattern: /\bnew\s+Function\s*\(/, label: 'new Function()' },
  { pattern: /\bimport\s*\(/, label: 'dynamic import()' },
  { pattern: /\brequire\s*\(/, label: 'require()' },
  { pattern: /\bchild_process\b/, label: 'child_process' },
  { pattern: /\bnode:/, label: 'node: builtin import' },
  { pattern: /\bprocess\s*\./, label: 'process.*' },
  { pattern: /\bglobalThis\b/, label: 'globalThis' },
  { pattern: /\bfetch\s*\(/, label: 'fetch()' },
  { pattern: /\bXMLHttpRequest\b/, label: 'XMLHttpRequest' },
  { pattern: /\bWebSocket\b/, label: 'WebSocket' },
  { pattern: /\b(atob|btoa)\s*\(/, label: 'atob/btoa' },
  {
    pattern: /\bBuffer\s*\.\s*from\s*\([^)]*base64/,
    label: 'base64 buffer decode',
  },
  { pattern: /\bfrom\s+['"]node:/, label: 'node: import' },
  { pattern: /\b__proto__\b/, label: '__proto__' },
  { pattern: /\[\s*['"]constructor['"]\s*\]/, label: "['constructor'] access" },
  { pattern: /\.\s*constructor\b/, label: '.constructor access' },
  { pattern: /\bReflect\s*\./, label: 'Reflect.*' },
  { pattern: /\bimport\s*\.\s*meta\b/, label: 'import.meta' },
  { pattern: /\bset(Timeout|Interval|Immediate)\s*\(/, label: 'timers' },
  {
    pattern: /\bfrom(CharCode|CodePoint)\b/,
    label: 'fromCharCode/fromCodePoint (possible obfuscation)',
  },
  { pattern: /\bString\s*\.\s*raw\b/, label: 'String.raw' },
  {
    pattern: /\\x[0-9a-fA-F]{2}/,
    label: 'hex-escaped string (possible obfuscation)',
  },
  {
    pattern: /\\u(\{[0-9a-fA-F]+\}|[0-9a-fA-F]{4})/,
    label: 'unicode-escaped string (possible obfuscation)',
  },
];

const importStatement = /(?:^|\n)\s*import\b[^;\n]*?from\s+['"]([^'"]+)['"]/g;

const listRuleFiles = (directory) => {
  const found = [];
  for (const entry of readdirSync(directory)) {
    const fullPath = join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      found.push(...listRuleFiles(fullPath));
    } else if (entry.endsWith('.ts')) {
      found.push(fullPath);
    }
  }
  return found;
};

const requestedFiles = process.argv.slice(2);
const files = (
  requestedFiles.length
    ? requestedFiles.map((file) => join(projectRoot, file))
    : listRuleFiles(rulesDir)
).filter((file) => file.includes(join('src', 'rules')) && file.endsWith('.ts'));

const violations = [];

for (const file of files) {
  const relativePath = relative(projectRoot, file);
  const isTestFile = file.endsWith('.test.ts');
  let source;
  try {
    source = readFileSync(file, 'utf8');
  } catch {
    continue;
  }

  for (const { pattern, label } of forbiddenConstructs) {
    if (pattern.test(source)) {
      violations.push(`${relativePath}: forbidden construct — ${label}`);
    }
  }

  // Rule examples are CDK snippets stored in template literals — data, not
  // code — and may legitimately contain their own import lines. Strip
  // template-literal contents for the import check only; the forbidden-
  // construct patterns above still scan the full source including examples.
  const sourceWithoutTemplateLiterals = source.replace(/`[^`]*`/g, '``');

  for (const match of sourceWithoutTemplateLiterals.matchAll(importStatement)) {
    const specifier = match[1];
    if (specifier.startsWith('.')) {
      continue;
    }
    const isAllowed = isTestFile && allowedBareImportsInTests.has(specifier);
    if (!isAllowed) {
      violations.push(
        `${relativePath}: disallowed import "${specifier}" — rules may only import from within the package${isTestFile ? ' (tests may also import "vitest")' : ''}`
      );
    }
  }
}

if (violations.length) {
  console.error('✗ security scan failed:\n');
  for (const violation of violations) {
    console.error(`  - ${violation}`);
  }
  console.error(
    `\n${violations.length} violation(s) across ${files.length} file(s).`
  );
  process.exit(1);
}

console.log(`✓ security scan clean (${files.length} rule file(s) checked).`);
