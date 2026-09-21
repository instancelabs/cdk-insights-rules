import { readFileSync, appendFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import {releaseGate} from './release-gate.mjs';
import { pushRepair } from './repair.mjs';
import { confirmedMerge } from './merge.mjs';
const env = process.env, repo = env.GITHUB_REPOSITORY;
const config = JSON.parse(readFileSync('.github/jarvis/config.json'));
assert(/^instancelabs\/[a-z0-9-]+$/.test(repo) && config.repository === repo, 'Repository is not enrolled');
assert(['aws','merge-only','amplify'].includes(config.releaseMode), 'Repository release adapter is not enabled');
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
 return releaseGate({repo,config,event:JSON.parse(readFileSync(env.GITHUB_EVENT_PATH)),eventName:env.GITHUB_EVENT_NAME,number:env.PR_NUMBER,ownerRequested:env.OWNER_REQUESTED==='true',ownerReviewed:env.OWNER_REVIEWED==='true',expectedSha:env.EXPECTED_SHA,actor:env.GITHUB_ACTOR,actorId:env.GITHUB_ACTOR_ID,dryRun:env.DRY_RUN==='true',api,pages,content,merge:confirmedMerge,pushRepair,output,summary,notifyRepair:async(number,sha,count)=>{
  await api(`${prefix}/issues/${number}/comments`,'POST',{body:`Jarvis restored ${count} unchanged bundled-package metadata entries at ${sha}. Waiting for fresh CI before any release.`});
  const r=await fetch(`https://api.telegram.org/bot${env.JARVIS_TELEGRAM_BOT_TOKEN}/sendMessage`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:'8037018914',text:`Jarvis repaired lockfile metadata in ${repo} #${number}. Fresh checks must pass before release.\nhttps://github.com/${repo}/pull/${number}`,disable_web_page_preview:true}),redirect:'error',signal:AbortSignal.timeout(20000)});assert(r.ok&&(await r.json()).ok,'Repair notification failed');
 }});
}
async function notify() {
  const sha = env.RELEASE_SHA;
  const held=env.RELEASE_STATE==='held';
  const mergeUnknown = env.GATE_RESULT === 'failure' && !sha;
  assert(held || mergeUnknown || /^[a-f0-9]{40}$/.test(sha));
  const pr = Number(env.PR_NUMBER); assert(Number.isSafeInteger(pr) && pr > 0);
  const link = `https://github.com/${repo}/actions/runs/${env.GITHUB_RUN_ID}`;
  const result = held ? 'was not released: '+String(env.HOLD_REASON||'release prerequisites are not met').slice(0,400) : mergeUnknown ? 'could not confirm the maintenance action after bounded recovery; deployment stopped. Inspect the run before retrying' : config.releaseMode === 'merge-only' ? 'merged the verified update; required CI passed. Package publication retains its existing release process' : env.PROD_RESULT === 'success' ? 'deployed to development and production; health checks passed' : `merged; development ${env.DEV_RESULT}; production ${env.PROD_RESULT}. Needs attention; no further promotion was attempted`;
  const text = `Jarvis: ${repo} #${pr} ${result}.\n${held ? 'No merge or deployment was performed' : 'Commit '+(sha ? sha.slice(0, 12) : 'unconfirmed')}\n${link}`;
  const marker = `<!-- jarvis-maintenance:${sha || env.GITHUB_RUN_ID} -->`;
  const comments = await pages(`/issues/${pr}/comments`);
  if (comments.some(c => c.user?.login === 'github-actions[bot]' && c.body?.includes(marker) && c.body?.includes(text))) return summary('This outcome was already notified.');
  const response = await fetch(`https://api.telegram.org/bot${env.JARVIS_TELEGRAM_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({chat_id:'8037018914',text,disable_web_page_preview:true}), redirect: 'error', signal: AbortSignal.timeout(20000) });
  assert(response.ok && (await response.json()).ok, 'Owner notification failed; inspect this workflow');
  await api(`${prefix}/issues/${pr}/comments`, 'POST', {body:`${marker}\n${text}`});
  summary(text);
}
if (process.argv[2] === 'notify') await notify(); else await gate();
