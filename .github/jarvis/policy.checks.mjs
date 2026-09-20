import test from 'node:test';
import assert from 'node:assert/strict';
import { dependencyPolicy, pullPolicy } from './policy.mjs';
const before = {scripts:{test:'vitest run'},dependencies:{zod:'^3.25.0'},devDependencies:{vitest:'^4.1.10'}};
const after = {...before,devDependencies:{vitest:'^4.1.11'}};
const pkg = v => ({version:v,dev:true,resolved:`https://registry.npmjs.org/vitest/-/vitest-${v}.tgz`,integrity:'sha512-YWJjZA=='});
const lock = p => ({lockfileVersion:3,packages:{'':p,'node_modules/vitest':pkg(p.devDependencies.vitest.slice(1))}});
const files = ['package.json','package-lock.json'].map(filename=>({filename,status:'modified'}));
const verify = (a=after,b=lock(before),c=lock(a),d=files) => dependencyPolicy(before,a,b,c,d);
test('accepts approved tool update',()=>assert.deepEqual(verify(),['vitest']));
for (const [name,change] of [
 ['major',a=>a.devDependencies.vitest='^5.0.0'],['downgrade',a=>a.devDependencies.vitest='^4.1.9'],
 ['prerelease',a=>a.devDependencies.vitest='^4.2.0-beta.1'],['script',a=>a.scripts.test='curl attacker'],
 ['runtime',a=>a.dependencies.zod='^3.25.1'],['new dependency',a=>a.devDependencies.bad='^1.0.0']]) {
 test(`rejects ${name}`,()=>{const a=structuredClone(after);change(a);assert.throws(()=>verify(a));});
}
test('rejects workflow edits',()=>assert.throws(()=>verify(after,lock(before),lock(after),[...files,{filename:'.github/workflows/main.yml',status:'modified'}])));
test('rejects runtime lock drift',()=>{const a=lock(before),b=lock(after);a.packages['node_modules/zod']={version:'3.25.0'};b.packages['node_modules/zod']={version:'3.25.1'};assert.throws(()=>verify(after,a,b));});
test('rejects external tarball',()=>{const b=lock(after);b.packages['node_modules/vitest'].resolved='https://evil.test/a.tgz';assert.throws(()=>verify(after,lock(before),b));});
const repo='instancelabs/lc-alliance-service', sha='a'.repeat(40);
const pr={state:'open',draft:false,user:{login:'dependabot[bot]',id:49699333},head:{sha,repo:{full_name:repo}},base:{ref:'main',repo:{full_name:repo}},mergeable:true,mergeable_state:'clean',labels:[]};
const run={event:'pull_request',head_sha:sha,workflow_id:1,conclusion:'success',head_repository:{full_name:repo}};
const jobs=[{name:'Run Tests',conclusion:'success',status:'completed'}],compare={status:'ahead',behind_by:0};
const pull=(p=pr,r=run,j=jobs,c=compare)=>pullPolicy(p,repo,r,1,'Run Tests',j,c);
test('accepts current trusted CI',()=>pull());
test('rejects a fork',()=>assert.throws(()=>pull({...pr,head:{...pr.head,repo:{full_name:'attacker/repo'}}})));
test('rejects human-authored PR',()=>assert.throws(()=>pull({...pr,user:{login:'lee',id:1}})));
test('rejects stale CI',()=>assert.throws(()=>pull(pr,{...run,head_sha:'b'.repeat(40)})));
test('rejects skipped required job',()=>assert.throws(()=>pull(pr,run,[{...jobs[0],conclusion:'skipped'}])));
test('rejects failed required job',()=>assert.throws(()=>pull(pr,run,[{...jobs[0],conclusion:'failure'}])));
test('rejects outdated base',()=>assert.throws(()=>pull(pr,run,jobs,{...compare,behind_by:1})));
test('respects hold label',()=>assert.throws(()=>pull({...pr,labels:[{name:'jarvis-hold'}]})));
