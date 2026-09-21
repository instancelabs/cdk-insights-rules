import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const source = dirname(fileURLToPath(import.meta.url));
const sha = '8'.repeat(40);
function run({ pr = {state:'open',merged:false}, jobs = [], mode = 'aws', comments = [], env = {}, failPr = false, failJobs = false } = {}) {
 const dir = mkdtempSync(join(tmpdir(), 'jarvis-notification-'));
 try {
  mkdirSync(join(dir,'.github/jarvis'),{recursive:true});
  cpSync(source,join(dir,'.github/jarvis'),{recursive:true,filter:p=>p===source || p.endsWith('.mjs')});
  writeFileSync(join(dir,'.github/jarvis/config.json'),JSON.stringify({repository:'instancelabs/lc-infrastructure',releaseMode:mode}));
  writeFileSync(join(dir,'mock.mjs'),`const f=${JSON.stringify({pr,jobs,comments,failPr,failJobs})}; const calls=[],messages=[];
  globalThis.fetch=async(url,o={})=>{calls.push({url,method:o.method||'GET'});let data;let status=200;
  if(url.startsWith('https://api.telegram.org/')){messages.push(JSON.parse(o.body).text);data={ok:true};}
  else if(url.includes('/comments'))data=o.method==='POST'?{}:f.comments;
  else if(url.includes('/pulls/42')){data=f.pr;if(f.failPr)status=503;}
  else if(url.includes('/jobs')){data={jobs:f.jobs};if(f.failJobs)status=403;}
  else throw Error('Unexpected API '+url);
  return {ok:status===200,status,json:async()=>data};};
  process.on('beforeExit',()=>console.log('RESULT:'+JSON.stringify({messages,calls})));`);
  const proc=spawnSync(process.execPath,['--import',join(dir,'mock.mjs'),join(dir,'.github/jarvis/maintain.mjs'),'notify'],{cwd:dir,encoding:'utf8',env:{PATH:process.env.PATH,GITHUB_REPOSITORY:'instancelabs/lc-infrastructure',GITHUB_RUN_ID:'35591877573',GITHUB_RUN_ATTEMPT:'1',PR_NUMBER:'42',RELEASE_STATE:'held',GATE_RESULT:'success',HOLD_REASON:'Major, prerelease, downgrade or incompatible zero-major changes require review.',...env}});
  assert.equal(proc.status,0,proc.stderr);
  return JSON.parse(proc.stdout.split('\n').find(x=>x.startsWith('RESULT:')).slice(7));
 } finally {rmSync(dir,{recursive:true,force:true});}
}
test('a stopped attempt checks the latest PR and never asks to review an already merged PR',()=>{
 const {messages,calls}=run({pr:{state:'closed',merged:true,merge_commit_sha:sha,merged_at:'2026-09-21T11:03:39Z'}});
 assert.match(messages[0],/^Information/);
 assert.match(messages[0],/already merged/i);
 assert.match(messages[0],/This attempt/i);
 assert.match(messages[0],/Your action: None/);
 assert.doesNotMatch(messages[0],/No merge or deployment was performed/);
 assert(calls.some(x=>x.url.includes('/pulls/42')));
});
test('open policy hold clearly requests review and identifies its attempt and PR',()=>{
 const text=run().messages[0];assert.match(text,/^Action needed/);assert.match(text,/Your action: Review PR #42/);assert.match(text,/Checked:/);assert.match(text,/Attempt: 35591877573\/1/);assert.match(text,/\/pull\/42/);
});
test('closed without merging is informational, not an obsolete approval request',()=>{
 const text=run({pr:{state:'closed',merged:false}}).messages[0];assert.match(text,/^Information/);assert.match(text,/closed without merging/);assert.match(text,/Your action: None/);
});
test('an unavailable PR lookup is never presented as an open PR or a confirmed merge',()=>{
 const text=run({failPr:true}).messages[0];assert.match(text,/^Action needed/);assert.match(text,/could not verify/i);assert.doesNotMatch(text,/PR is open|already merged|Your action: Review/);
});
test('production health gate failure before deployment is distinct from a failed deployment',()=>{
 const text=run({pr:{state:'closed',merged:true,merge_commit_sha:sha},env:{RELEASE_STATE:'merged',RELEASE_SHA:sha,DEV_RESULT:'success',PROD_RESULT:'failure'},jobs:[{name:'production / Deploy and verify',steps:[{name:'Verify maintenance stack, runtime and alarm health',conclusion:'failure'},{name:'Deploy every stack with rollback enabled',conclusion:'skipped'}]}]}).messages[0];
 assert.match(text,/^Action needed/);assert.match(text,/Development: Deployment and verification passed/);assert.match(text,/Production: Blocked before deployment/);assert.match(text,/health/);assert.match(text,/Your action:/);
});
test('a deployment step failure does not claim that production was unchanged',()=>{
 const text=run({pr:{state:'closed',merged:true,merge_commit_sha:sha},env:{RELEASE_STATE:'merged',RELEASE_SHA:sha,DEV_RESULT:'success',PROD_RESULT:'failure'},jobs:[{name:'production / Deploy and verify',steps:[{name:'Deploy every stack with rollback enabled',conclusion:'failure'}]}]}).messages[0];
 assert.match(text,/deployment or verification failed/i);assert.doesNotMatch(text,/Blocked before deployment|production was unchanged/i);
});
test('a successful release is informational, with no owner action',()=>{
 const text=run({pr:{state:'closed',merged:true,merge_commit_sha:sha},env:{RELEASE_STATE:'merged',RELEASE_SHA:sha,DEV_RESULT:'success',PROD_RESULT:'success'}}).messages[0];assert.match(text,/^Information/);assert.match(text,/Production: Deployment and verification passed/);assert.match(text,/Your action: None/);
});
test('merge-only repositories never claim a package publication',()=>{
 const text=run({mode:'merge-only',pr:{state:'closed',merged:true,merge_commit_sha:sha},env:{RELEASE_STATE:'merged',RELEASE_SHA:sha}}).messages[0];assert.match(text,/^Information/);assert.match(text,/Package publication is separate/);assert.match(text,/Your action: None/);
});
test('missing job details cannot turn a failure into a before-deployment claim',()=>{
 const text=run({failJobs:true,pr:{state:'closed',merged:true},env:{RELEASE_STATE:'merged',RELEASE_SHA:sha,DEV_RESULT:'success',PROD_RESULT:'failure'}}).messages[0];assert.match(text,/^Action needed/);assert.match(text,/exact failing step could not be verified/i);assert.doesNotMatch(text,/Blocked before deployment/);
});
test('a stopped wait does not promise that work is still running',()=>{
 const text=run({env:{HOLD_REASON:'Current-head CI did not become ready within the bounded wait; nothing released'}}).messages[0];assert.match(text,/^Action needed/);assert.match(text,/stopped/i);assert.doesNotMatch(text,/^In progress|I will retry|automatically retry/);
});
test('a rerun is idempotent even when the checked timestamp changes',()=>{
 const result=run({comments:[{user:{login:'github-actions[bot]'},body:'<!-- jarvis-notification:v2:35591877573:1 -->\nAn earlier rendering'}]});assert.equal(result.messages.length,0);
});
test('an uncertain merge can be reconciled, but is never mistaken for a deployment',()=>{
 const text=run({pr:{state:'closed',merged:true,merge_commit_sha:sha},env:{RELEASE_STATE:'merge-unconfirmed',GATE_RESULT:'failure'}}).messages[0];assert.match(text,/already merged/);assert.match(text,/Deployment.*not verified/i);assert.match(text,/^Action needed/);
});
