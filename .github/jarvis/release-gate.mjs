import assert from 'node:assert/strict';
import {dependencyPolicy,pullPolicy,repairLockMetadata} from './policy.mjs';
import {ownerDependencyPolicy,ownerRequestPolicy,sourceRepairPolicy} from './release-policy.mjs';
export async function releaseGate({repo,config,event,eventName,number,ownerRequested=false,ownerReviewed=false,expectedSha,actor,actorId,dryRun=false,api,pages,content,merge,pushRepair,output=()=>{},summary=()=>{},notifyRepair=async()=>{},wait=ms=>new Promise(r=>setTimeout(r,ms)),waitAttempts=30}){
 const prefix=`/repos/${repo}`;let prNumber=Number(number),attemptingMerge=false,approvedHead=expectedSha,repaired=false;
 if(eventName==='workflow_run'){
  const r=event.workflow_run;
  if(r?.event!=='pull_request'||r.conclusion!=='success'||r.pull_requests?.length!==1)return summary('No eligible pull request in this event.');
  prNumber=r.pull_requests[0].number;
 }
 assert(Number.isSafeInteger(prNumber)&&prNumber>0,'PR number required');output('pr',prNumber);
 const hold=error=>{const reason=String(error.message).split('\n')[0].slice(0,400);output('state','held');output('hold_reason',reason);summary(`Held PR #${prNumber}: ${reason}`);return {state:'held',reason};};
 try{
  let pr=await api(`${prefix}/pulls/${prNumber}`);
  assert(!ownerReviewed||ownerRequested,'Reviewed releases require owner authentication');
  if(ownerRequested)ownerRequestPolicy(eventName,actor,actorId,approvedHead,pr);
  const wf=await api(`${prefix}/actions/workflows/${config.ciWorkflow}`);
  const maxPasses=waitAttempts;
  for(let attempt=0;attempt<maxPasses;attempt++){
   pr=await api(`${prefix}/pulls/${prNumber}`);assert(pr.state==='open','PR is no longer open; inspect its actual state');
   if(ownerRequested)assert(pr.head.sha===approvedHead,'PR changed after the release request; inspect and request its new commit');
   const current=(await api(`${prefix}/git/ref/heads/main`)).object.sha;
   const comparison=await api(`${prefix}/compare/${current}...${pr.head.sha}`);
   assert(comparison.behind_by===0&&comparison.status==='ahead','PR must include current main; update its branch and request the new commit');
   const runs=await api(`${prefix}/actions/workflows/${wf.id}/runs?event=pull_request&head_sha=${pr.head.sha}&per_page=20`);
   const run=runs.workflow_runs[0];
   const pending=!run||run.status!=='completed'||pr.mergeable===null||pr.mergeable_state==='unknown';
   if(pending&&attempt<maxPasses-1){output('state','waiting');if(attempt===0)summary(`Waiting for current-head CI for PR #${prNumber}.`);await wait(20000);continue;}
   assert(run,'Current PR has no trusted CI run');
   const jobs=await pages(`/actions/runs/${run.id}/jobs`,'jobs');
   // A clean mergeable state includes all native required checks and protections.
   if(run.conclusion==='success'&&pr.mergeable_state==='blocked'&&attempt<maxPasses-1){output('state','waiting');await wait(20000);continue;}
   pullPolicy(pr,repo,run,wf.id,config.check,jobs,comparison,{allowRepair:ownerRequested,allowReviewed:ownerRequested&&ownerReviewed});
   const files=await pages(`/pulls/${prNumber}/files`);assert(files.length===pr.changed_files,'Complete PR diff required');
   let changes;
   if(ownerReviewed){
    assert(files.length>0,'A reviewed release must have a complete non-empty diff');
    changes=[`owner-reviewed PR at ${approvedHead}`];
   }else if(pr.user.login==='instance-labs-jarvis-repair[bot]'){
    assert(ownerRequested,'A source repair requires an owner release request');changes=sourceRepairPolicy(pr,files);
   }else{
    const [before,after,oldLock,newLock]=await Promise.all(['package.json','package.json','package-lock.json','package-lock.json'].map((f,i)=>content(f,i%2?pr.head.sha:current)));
    try{changes=(ownerRequested?ownerDependencyPolicy:dependencyPolicy)(before,after,oldLock,newLock,files);}
    catch(policyError){
     let repair;try{repair=repairLockMetadata(before,after,oldLock,newLock,files,ownerRequested?ownerDependencyPolicy:dependencyPolicy);}catch{throw policyError;}
     const comments=await pages(`/issues/${prNumber}/comments`);
     assert(!repaired&&!comments.some(c=>c.user?.login==='github-actions[bot]'&&c.body?.includes('<!-- jarvis-repair:v2 -->')),'A repair was already attempted; inspect it before another release request');
     if(dryRun){output('state','repair-needed');return summary(`PR #${prNumber} needs one bounded lockfile metadata repair and fresh CI.`);}
     await api(`${prefix}/issues/${prNumber}/comments`,'POST',{body:'<!-- jarvis-repair:v2 -->\nJarvis is restoring only unchanged bundled-package metadata. Fresh CI is required before release.'});
     const repairedHead=await pushRepair({repo,branch:pr.head.ref,head:pr.head.sha,base:current,content:JSON.stringify(repair.lock,null,2)+'\n'});
     repaired=true;output('state','repair-pushed');await notifyRepair(prNumber,repairedHead,repair.paths.length);
     if(!ownerRequested)return {state:'repair-pushed',sha:repairedHead};
     // The same authorised workflow may wait for the exact deterministic repair it created.
     approvedHead=repairedHead;await wait(20000);continue;
    }
   }
   assert((await api(`${prefix}/git/ref/heads/main`)).object.sha===current,'Main changed; fresh CI is required');
   assert((await api(`${prefix}/pulls/${prNumber}`)).head.sha===pr.head.sha,'PR changed; fresh CI is required');
   summary(`Eligible PR #${prNumber}: ${changes.join(', ')}; CI ${run.id}; commit ${pr.head.sha}.`);
   if(dryRun){output('eligible','true');output('state','eligible');return {state:'eligible'};}
   attemptingMerge=true;output('state','merging');const mergedSha=await merge({request:api,repo,number:prNumber,head:pr.head.sha,base:current,title:pr.title+` (#${prNumber})`});
   output('sha',mergedSha);output('state','merged');summary(`Merged #${prNumber} as ${mergedSha}. ${config.releaseMode==='merge-only'?'Package publication retains its existing release process.':'Development must pass before production.'}`);return {state:'merged',sha:mergedSha};
  }
  return hold(Error('Current-head CI did not become ready within the bounded wait; nothing released'));
 }catch(e){if(attemptingMerge){output('state','merge-unconfirmed');throw e;}return hold(e);}
}
