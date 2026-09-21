import { readFileSync, appendFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import {releaseGate} from './release-gate.mjs';
import { pushRepair } from './repair.mjs';
import { confirmedMerge } from './merge.mjs';
import { notifyRelease, repairMessage } from './notification.mjs';
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
  const r=await fetch(`https://api.telegram.org/bot${env.JARVIS_TELEGRAM_BOT_TOKEN}/sendMessage`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:'8037018914',text:repairMessage({repo,number,sha}),disable_web_page_preview:true}),redirect:'error',signal:AbortSignal.timeout(20000)});assert(r.ok&&(await r.json()).ok,'Repair notification failed');
 }});
}
async function notify() { return notifyRelease({repo, config, env, api, pages, summary}); }
if (process.argv[2] === 'notify') await notify(); else await gate();
