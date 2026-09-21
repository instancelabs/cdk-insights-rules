import assert from 'node:assert/strict';

const clean = value => String(value || '').replace(/[\r\n]+/g, ' ').slice(0, 400);
const stamp = date => new Intl.DateTimeFormat('en-GB', {timeZone:'Europe/London',dateStyle:'medium',timeStyle:'long'}).format(date);

function stageResult(name, result, jobs) {
 if (result === 'success') return `${name}: Deployment and verification passed.`;
 if (result === 'skipped' || !result) return `${name}: Not run by this attempt.`;
 const matching = (jobs || []).filter(j => j.name.toLowerCase().startsWith(name.toLowerCase() + ' /'));
 const failed = matching.flatMap(j => (j.steps || []).filter(s => s.conclusion === 'failure'));
 const deployments = matching.flatMap(j => (j.steps || []).filter(s => /^Deploy every stack|^Deploy CDK|^Deploy to Amplify/i.test(s.name)));
 // Only claim "before deployment" when the deployment steps are explicitly skipped.
 const before = failed.length > 0 && deployments.length > 0 && deployments.every(s => s.conclusion === 'skipped');
 if (before) return `${name}: Blocked before deployment. Failed check: ${clean(failed[0].name)}.`;
 if (failed.length) return `${name}: The deployment or verification failed at “${clean(failed[0].name)}”. The live environment needs checking.`;
 if (result === 'cancelled') return `${name}: Cancelled; the live environment was not verified.`;
 return `${name}: The release did not pass; the exact failing step could not be verified. Check the run before retrying.`;
}

export function releaseMessage({repo, pr, env, config, current, jobs, checkedAt = new Date()}) {
 const held = env.RELEASE_STATE === 'held';
 const sha = env.RELEASE_SHA || '';
 const uncertain = env.GATE_RESULT === 'failure' && !sha;
 const reason = clean(env.HOLD_REASON || 'Release prerequisites were not met.');
 const merged = current?.merged === true;
 const closed = current?.state === 'closed' && current?.merged === false;
 const snapshot = merged ? `PR #${pr} is already merged${current.merge_commit_sha ? ` at ${current.merge_commit_sha.slice(0,12)}` : ''}.`
  : closed ? `PR #${pr} is closed without merging.`
  : current?.state === 'open' ? `PR #${pr} is open.` : 'Could not verify the latest PR state.';
 let label = 'Action needed', headline, details, action;
 if (held) {
  headline = 'Release attempt stopped';
  details = [`This attempt stopped before merging or deploying. Reason: ${reason}`,`Latest check: ${snapshot}`];
  if (merged || closed) {
   label = 'Information';
   details.push('Deployment status from other runs is not verified by this notice.');
   action = 'None for this stopped attempt. Do not retry or approve it based on this old hold.';
  } else if (!current) {
   action = `Ask Jarvis to check PR #${pr} and the latest release runs before taking any merge or deployment action.`;
  } else if (/require review|requires.*review|owner.*review|review.*required/i.test(reason)) {
   action = `Review PR #${pr}. If you approve it, tell Jarvis “I reviewed ${repo.split('/')[1]} PR #${pr}; please merge and deploy.” Jarvis must recheck the current commit and required checks.`;
  } else {
   action = `Ask Jarvis to investigate this stopped attempt for ${repo.split('/')[1]} PR #${pr}. No repair or retry is confirmed by this notice.`;
  }
 } else if (uncertain) {
  headline = 'Release needs verification';
  details = ['This attempt could not confirm its merge and stopped before deployment.',`Latest check: ${snapshot}`,'Deployment status is not verified by this notice.'];
  action = `Ask Jarvis to reconcile PR #${pr} and its latest release runs before retrying. Do not merge it again if already merged.`;
 } else {
  const success = config.releaseMode === 'merge-only' || (env.DEV_RESULT === 'success' && env.PROD_RESULT === 'success');
  label = success ? 'Information' : 'Action needed';
  headline = config.releaseMode === 'merge-only' ? 'Update merged' : success ? 'Release completed' : 'Release incomplete';
  details = [`This attempt: Merge verified at ${sha.slice(0,12)}.`,`Latest check: ${snapshot}`];
  if (config.releaseMode === 'merge-only') details.push('Package publication is separate; this workflow did not publish a package.');
  else details.push(stageResult('Development',env.DEV_RESULT,jobs),stageResult('Production',env.PROD_RESULT,jobs));
  action = success ? 'None.' : `Ask Jarvis to investigate the failed release for ${repo.split('/')[1]} PR #${pr} and check the latest run before retrying. The PR does not need merging again.`;
 }
 return `${label} — ${headline}\n${repo} #${pr}\n\n${details.join('\n')}\n\nYour action: ${action}\nChecked: ${stamp(checkedAt)}\nAttempt: ${env.GITHUB_RUN_ID}/${env.GITHUB_RUN_ATTEMPT || '1'}\nPR: https://github.com/${repo}/pull/${pr}\nRun: https://github.com/${repo}/actions/runs/${env.GITHUB_RUN_ID}`;
}

export function repairMessage({repo,number,sha,checkedAt = new Date()}) {
 return `In progress — Repair submitted for checks\n${repo} #${number}\n\nJarvis repaired lockfile metadata at ${sha.slice(0,12)}. Fresh checks must pass before any release. This is not a merge or deployment confirmation.\n\nYour action: None while checks run.\nChecked: ${stamp(checkedAt)}\nPR: https://github.com/${repo}/pull/${number}`;
}

export async function notifyRelease({repo,config,env,api,pages,summary,send=fetch,now=()=>new Date()}) {
 const sha = env.RELEASE_SHA;
 assert(env.RELEASE_STATE === 'held' || (env.GATE_RESULT === 'failure' && !sha) || /^[a-f0-9]{40}$/.test(sha));
 const pr = Number(env.PR_NUMBER); assert(Number.isSafeInteger(pr) && pr > 0);
 assert(/^\d+$/.test(env.GITHUB_RUN_ID));
 const attempt = env.GITHUB_RUN_ATTEMPT || '1'; assert(/^\d+$/.test(attempt));
 // The identity is the attempt, not the rendering time or commit shared by multiple releases.
 const marker = `<!-- jarvis-notification:v2:${env.GITHUB_RUN_ID}:${attempt} -->`;
 const comments = await pages(`/issues/${pr}/comments`);
 if (comments.some(c => c.user?.login === 'github-actions[bot]' && c.body?.includes(marker))) return summary('This attempt was already notified.');
 let current = null, jobs = null;
 try {
  const p = await api(`/repos/${repo}/pulls/${pr}`);
  if (['open','closed'].includes(p?.state) && typeof p.merged === 'boolean') current = p;
 } catch { /* Keep the lack of evidence explicit in the message. */ }
 if (sha && config.releaseMode !== 'merge-only' && (env.DEV_RESULT !== 'success' || env.PROD_RESULT !== 'success')) {
  try { jobs = await pages(`/actions/runs/${env.GITHUB_RUN_ID}/attempts/${attempt}/jobs`, 'jobs'); } catch { /* Never infer a deployment stage without evidence. */ }
 }
 const text = releaseMessage({repo,pr,config,env,current,jobs,checkedAt:now()});
 const response = await send(`https://api.telegram.org/bot${env.JARVIS_TELEGRAM_BOT_TOKEN}/sendMessage`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:'8037018914',text,disable_web_page_preview:true}),redirect:'error',signal:AbortSignal.timeout(20000)});
 assert(response.ok && (await response.json()).ok,'Owner notification failed; inspect this workflow');
 await api(`/repos/${repo}/issues/${pr}/comments`,'POST',{body:`${marker}\n${text}`});
 summary(text);
}
