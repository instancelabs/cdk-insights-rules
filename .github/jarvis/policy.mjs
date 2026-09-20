import assert from 'node:assert/strict';
import { isDeepStrictEqual } from 'node:util';
const allowed = /^(vitest|@vitest\/[a-z0-9-]+|typescript|@types\/[a-z0-9-]+|@biomejs\/biome|@commitlint\/[a-z0-9-]+|husky|ts-node|tsx)$/;
const version = x => {
  const m = /^(\^|~)?(\d+)\.(\d+)\.(\d+)$/.exec(x ?? '');
  assert(m, 'Only stable, simple semver ranges are allowed');
  return [m[1] || '', ...m.slice(2).map(Number)];
};
export function dependencyPolicy(before, after, oldLock, newLock, files) {
  assert(files.length > 0 && files.length <= 2 && files.every(x => ['package.json', 'package-lock.json'].includes(x.filename) && x.status === 'modified'), 'Only existing root npm manifests may change');
  const a = structuredClone(before), b = structuredClone(after);
  delete a.devDependencies; delete b.devDependencies;
  assert(isDeepStrictEqual(a, b), 'Runtime dependencies, scripts, overrides and package metadata require review');
  const names = Object.keys(before.devDependencies || {});
  assert(isDeepStrictEqual(names.sort(), Object.keys(after.devDependencies || {}).sort()), 'Adding or removing dependencies requires review');
  const changes = [];
  for (const name of names) {
    if (before.devDependencies[name] === after.devDependencies[name]) continue;
    assert(allowed.test(name), `Package requires review: ${name}`);
    const [range, major, minor, patch] = version(before.devDependencies[name]);
    const [newRange, newMajor, newMinor, newPatch] = version(after.devDependencies[name]);
    assert(range === newRange && major > 0 && major === newMajor && (newMinor > minor || newMinor === minor && newPatch > patch), 'Major, prerelease, zero-major and downgrade changes require review');
    changes.push(name);
  }
  assert(changes.length > 0 && changes.length <= 5, 'Expected 1–5 approved direct development dependency updates');
  assert(oldLock.lockfileVersion >= 2 && newLock.lockfileVersion === oldLock.lockfileVersion, 'Unsupported lockfile format change');
  assert(isDeepStrictEqual(newLock.packages?.['']?.devDependencies, after.devDependencies), 'Manifest and lockfile must agree');
  assert(isDeepStrictEqual(newLock.packages?.['']?.dependencies, after.dependencies), 'Runtime manifest and lockfile must agree');
  const oldPackages = oldLock.packages || {}, newPackages = newLock.packages || {};
  for (const path of new Set([...Object.keys(oldPackages), ...Object.keys(newPackages)])) {
    if (!path || isDeepStrictEqual(oldPackages[path], newPackages[path])) continue;
    const old = oldPackages[path], next = newPackages[path];
    assert((!old || old.dev === true) && (!next || next.dev === true), `Runtime lockfile change requires review: ${path}`);
    if (next) {
      assert(path.startsWith('node_modules/') && !next.link, 'Linked dependencies require review');
      const url = new URL(next.resolved);
      assert(url.protocol === 'https:' && url.hostname === 'registry.npmjs.org' && !url.username && !url.password && !url.port, 'Only npm registry packages are allowed');
      assert(/^sha512-[A-Za-z0-9+/=]+$/.test(next.integrity), 'Package integrity is required');
    }
  }
  return changes;
}
export function pullPolicy(pr, repo, run, workflowId, checkName, jobs, comparison) {
  assert(pr.state === 'open' && !pr.draft && pr.user?.login === 'dependabot[bot]' && pr.user?.id === 49699333, 'Only open Dependabot PRs are eligible');
  assert(pr.head?.repo?.full_name === repo && pr.base?.repo?.full_name === repo && pr.base.ref === 'main', 'Forks and non-main targets are excluded');
  assert(pr.mergeable === true && pr.mergeable_state === 'clean', 'PR must be mergeable with all branch rules met');
  assert(run.event === 'pull_request' && run.head_sha === pr.head.sha && run.workflow_id === workflowId && run.conclusion === 'success', 'Successful trusted CI for the current PR commit is required');
  assert(run.head_repository?.full_name === repo, 'CI must be from this repository');
  const check = jobs.filter(j => j.name === checkName);
  assert(check.length === 1 && check[0].conclusion === 'success' && check[0].status === 'completed', 'Required CI job must succeed, not skip');
  assert(comparison.behind_by === 0 && comparison.status === 'ahead', 'PR must include current main');
  assert(!pr.labels?.some(l => ['jarvis-hold', 'do-not-merge'].includes(l.name)), 'Automation is paused for this PR');
}

// npm sometimes removes boolean `extraneous` annotations from CDK-bundled
// runtime packages during a development-tool update. Restore only that metadata;
// resolved versions, hashes, URLs, scripts and dependency edges must be identical.
export function repairLockMetadata(before, after, oldLock, candidate, files) {
  const repaired = structuredClone(candidate), changed = [];
  for (const path of new Set([...Object.keys(oldLock.packages || {}), ...Object.keys(candidate.packages || {})])) {
    if (!path) continue;
    const old = oldLock.packages[path], next = candidate.packages[path];
    if (isDeepStrictEqual(old, next) || ((!old || old.dev === true) && (!next || next.dev === true))) continue;
    assert(old && next && path.startsWith('node_modules/'), 'A runtime package was added or removed');
    for (const entry of [old, next]) assert(!('extraneous' in entry) || typeof entry.extraneous === 'boolean', 'Invalid metadata flag');
    const a = {...old}, b = {...next}; delete a.extraneous; delete b.extraneous;
    assert(isDeepStrictEqual(a, b), 'Runtime contents changed; no automatic repair');
    repaired.packages[path] = structuredClone(old); changed.push(path);
  }
  assert(changed.length > 0 && changed.length <= 20, 'No bounded metadata repair is available');
  dependencyPolicy(before, after, oldLock, repaired, files);
  return {lock:repaired, paths:changed};
}
