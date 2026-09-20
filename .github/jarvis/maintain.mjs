import { readFileSync, appendFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { dependencyPolicy, pullPolicy, repairLockMetadata } from './policy.mjs';
import { pushRepair } from './repair.mjs';
import { confirmedMerge } from './merge.mjs';
const env = process.env, repo = env.GITHUB_REPOSITORY;
const config = JSON.parse(readFileSync('.github/jarvis/config.json'));
assert(/^instancelabs\/[a-z0-9-]+$/.test(repo) && config.repository === repo, 'Repository is not enrolled');
assert(['aws','merge-only'].includes(config.releaseMode), 'Repository release adapter is not enabled');
const prefix = `/repos/${repo}`;
export async function api(path, method = 'GET', body) {
  assert(path.startsWith(prefix + '/'), 'Unexpected API path');
  const res = await fetch('https://api.github.com' + path, { method, headers: { Authorization: `Bearer ${env.GH_TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, body: body ? JSON.stringify(body) : undefined, redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw Object.assign(new Error(`GitHub ${method} ${path.split('?')[0]} returned ${res.status}`),{status:res.status});
  return res.status === 204 ? null : res.json();
}
async function pages(path, key) {
  const result = [];
  for (let page = 1; page <= 10; page++) {
    const data = await api(prefix + path + (path.includes('?') ? '&' : '?') + `per_page=100&page=${page}`);
    const rows = key ? data[key] : data;
    result.push(...rows);
    if (rows.length < 100) return result;
  }
  throw Error('Too many API pages; review required');
}
function output(key, value) { if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `${key}=${value}\n`); }
function summary(text) { console.log(text); if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, text + '\n'); }
async function content(path, sha) {
  assert(/^[a-f0-9]{40}$/.test(sha));
  const x = await api(`${prefix}/contents/${path}?ref=${sha}`);
  assert(x.encoding === 'base64' && x.size < 2000000, 'Unexpected manifest response');
  return JSON.parse(Buffer.from(x.content, 'base64').toString());
}
async function gate() {
  const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH));
  let number, run;
  const wf = await api(`${prefix}/actions/workflows/${config.ciWorkflow}`);
  if (env.GITHUB_EVENT_NAME === 'workflow_run') {
    run = event.workflow_run;
    if (run.event !== 'pull_request' || run.conclusion !== 'success' || run.pull_requests.length !== 1) return summary('No eligible pull request in this event.');
    number = run.pull_requests[0].number;
  } else {
    number = Number(env.PR_NUMBER);
    assert(Number.isSafeInteger(number) && number > 0, 'PR number required');
    const pr = await api(`${prefix}/pulls/${number}`);
    const runs = await api(`${prefix}/actions/workflows/${wf.id}/runs?event=pull_request&head_sha=${pr.head.sha}&per_page=20`);
    run = runs.workflow_runs[0];
    assert(run, 'Current PR has no CI run');
  }
  output('pr', number);
  let attemptingMerge = false;
  try {
    const pr = await api(`${prefix}/pulls/${number}`);
    const current = (await api(`${prefix}/git/ref/heads/main`)).object.sha;
    const compare = await api(`${prefix}/compare/${current}...${pr.head.sha}`);
    const jobs = await pages(`/actions/runs/${run.id}/jobs`, 'jobs');
    pullPolicy(pr, repo, run, wf.id, config.check, jobs, compare);
    const files = await pages(`/pulls/${number}/files`);
    const [before, after, oldLock, newLock] = await Promise.all(['package.json', 'package.json', 'package-lock.json', 'package-lock.json'].map((f, i) => content(f, i % 2 ? pr.head.sha : current)));
    let changes;
    try { changes = dependencyPolicy(before, after, oldLock, newLock, files); }
    catch (policyError) {
      let repair;
      try { repair = repairLockMetadata(before, after, oldLock, newLock, files); }
      catch { throw policyError; }
      const comments = await pages(`/issues/${number}/comments`);
      assert(!comments.some(c=>c.user?.login==='github-actions[bot]' && c.body?.includes('<!-- jarvis-repair:v1 -->')), 'A repair was already attempted; review required');
      summary(`PR #${number}: can restore ${repair.paths.length} harmless lockfile metadata entries; runtime contents are unchanged.`);
      if (env.DRY_RUN === 'true') return;
      // Record the attempt before any branch mutation. A timeout cannot cause
      // another automatic attempt to overwrite a concurrent human change.
      await api(`${prefix}/issues/${number}/comments`, 'POST', {body:'<!-- jarvis-repair:v1 -->\nJarvis is attempting one bounded lockfile metadata repair. Fresh CI must pass before any merge.'});
      attemptingMerge = true; // API mutation failures must surface, never become a silent hold.
      const repairSha = await pushRepair({repo,branch:pr.head.ref,head:pr.head.sha,base:current,content:JSON.stringify(repair.lock,null,2)+'\n'});
      await api(`${prefix}/issues/${number}/comments`, 'POST', {body:`Jarvis restored harmless npm metadata in ${repair.paths.length} entries at ${repairSha}. Runtime package versions, integrity hashes and dependency edges are unchanged. Waiting for fresh CI.`});
      const notice = await fetch(`https://api.telegram.org/bot${env.JARVIS_TELEGRAM_BOT_TOKEN}/sendMessage`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:'8037018914',text:`Jarvis repaired harmless lockfile metadata in ${repo} #${number}. Fresh checks will run before merging or deploying.\nhttps://github.com/${repo}/pull/${number}`,disable_web_page_preview:true}),redirect:'error',signal:AbortSignal.timeout(20000)});
      assert(notice.ok && (await notice.json()).ok, 'Repair notification failed');
      return summary('Repair pushed with a repository-scoped App token; GitHub will trigger fresh PR checks.');
    }
    // Re-read both refs before mutation. The merge API pins the PR head, and
    // strict branch protection rejects a base race rather than bypassing it.
    assert((await api(`${prefix}/git/ref/heads/main`)).object.sha === current, 'Main changed; wait for fresh CI');
    assert((await api(`${prefix}/pulls/${number}`)).head.sha === pr.head.sha, 'PR changed; wait for fresh CI');
    summary(`Eligible PR #${number}: ${changes.join(', ')}; CI ${run.id}; commit ${pr.head.sha}.`);
    if (env.DRY_RUN === 'true') return output('eligible', 'true');
    attemptingMerge = true;
    const mergedSha = await confirmedMerge({request:api,repo,number,head:pr.head.sha,base:current});
    output('sha', mergedSha);
    summary(`Merged #${number} as ${mergedSha}. ${config.releaseMode === 'aws' ? 'Development must pass before production.' : 'Development-tool update verified; no package publication is needed.'}`);
  } catch (error) {
    if (attemptingMerge) throw error;
    summary(`Held PR #${number}: ${error.message.split('\n')[0]}`);
    // Eligibility holds are expected and do not cause notification noise.
    // Mutation failures remain visible in the workflow summary; no deployment
    // is possible without a confirmed merge SHA.
  }
}
async function notify() {
  const sha = env.RELEASE_SHA;
  const mergeUnknown = env.GATE_RESULT === 'failure' && !sha;
  assert(mergeUnknown || /^[a-f0-9]{40}$/.test(sha));
  const pr = Number(env.PR_NUMBER); assert(Number.isSafeInteger(pr) && pr > 0);
  const link = `https://github.com/${repo}/actions/runs/${env.GITHUB_RUN_ID}`;
  const result = mergeUnknown ? 'could not confirm the maintenance action after bounded recovery; deployment stopped. Inspect the run before retrying' : config.releaseMode === 'merge-only' ? 'merged the verified development-tool update; required CI passed, no package publication was performed' : env.PROD_RESULT === 'success' ? 'deployed to development and production; health checks passed' : `merged; development ${env.DEV_RESULT}; production ${env.PROD_RESULT}. Needs attention; no further promotion was attempted`;
  const text = `Jarvis: ${repo} #${pr} ${result}.\nCommit ${sha ? sha.slice(0, 12) : 'unconfirmed'}\n${link}`;
  const marker = `<!-- jarvis-maintenance:${sha || env.GITHUB_RUN_ID} -->`;
  const comments = await pages(`/issues/${pr}/comments`);
  if (comments.some(c => c.user?.login === 'github-actions[bot]' && c.body?.includes(marker) && c.body?.includes(text))) return summary('This outcome was already notified.');
  const response = await fetch(`https://api.telegram.org/bot${env.JARVIS_TELEGRAM_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({chat_id:'8037018914',text,disable_web_page_preview:true}), redirect: 'error', signal: AbortSignal.timeout(20000) });
  assert(response.ok && (await response.json()).ok, 'Owner notification failed; inspect this workflow');
  await api(`${prefix}/issues/${pr}/comments`, 'POST', {body:`${marker}\n${text}`});
  summary(text);
}
if (process.argv[2] === 'notify') await notify(); else await gate();
