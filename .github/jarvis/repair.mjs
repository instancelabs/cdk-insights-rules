import assert from 'node:assert/strict';
import { createSign } from 'node:crypto';

export async function writeRepair({request, repo, branch, head, base, content}) {
  const prefix = `/repos/${repo}`;
  assert(/^dependabot\/npm_and_yarn\/[A-Za-z0-9_./-]+$/.test(branch) && !branch.includes('..'), 'Unexpected repair branch');
  assert(/^[a-f0-9]{40}$/.test(head) && /^[a-f0-9]{40}$/.test(base), 'Invalid source commit');
  assert(Buffer.byteLength(content) < 2000000, 'Lockfile too large');
  assert((await request(`${prefix}/git/ref/heads/${branch}`)).object.sha === head, 'PR changed before repair');
  assert((await request(`${prefix}/git/ref/heads/main`)).object.sha === base, 'Main changed before repair');
  const parent = await request(`${prefix}/git/commits/${head}`);
  const blob = await request(`${prefix}/git/blobs`, 'POST', {content, encoding:'utf-8'});
  const tree = await request(`${prefix}/git/trees`, 'POST', {base_tree:parent.tree.sha, tree:[{path:'package-lock.json',mode:'100644',type:'blob',sha:blob.sha}]});
  const commit = await request(`${prefix}/git/commits`, 'POST', {message:'fix(deps): restore unchanged runtime lock metadata [jarvis-repair-v1]', tree:tree.sha, parents:[head]});
  assert((await request(`${prefix}/git/ref/heads/${branch}`)).object.sha === head, 'PR changed; repair was not pushed');
  assert((await request(`${prefix}/git/ref/heads/main`)).object.sha === base, 'Main changed; repair was not pushed');
  // No force push. A concurrent commit makes this non-fast-forward and fails.
  await request(`${prefix}/git/refs/heads/${branch}`, 'PATCH', {sha:commit.sha,force:false});
  return commit.sha;
}
export async function pushRepair(options) {
  const env=process.env,now=Math.floor(Date.now()/1000);
  assert(/^\d+$/.test(env.JARVIS_REPAIR_APP_ID || '') && /^\d+$/.test(env.JARVIS_REPAIR_INSTALLATION_ID || ''), 'Repair credentials are unavailable');
  const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
  const unsigned=b64({alg:'RS256',typ:'JWT'})+'.'+b64({iat:now-60,exp:now+540,iss:env.JARVIS_REPAIR_APP_ID});
  const signer=createSign('RSA-SHA256');signer.update(unsigned);signer.end();
  const jwt=unsigned+'.'+signer.sign(env.JARVIS_REPAIR_APP_PRIVATE_KEY).toString('base64url');
  const call=async(path,token,method='GET',body)=>{
    const res=await fetch('https://api.github.com'+path,{method,headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,redirect:'error',signal:AbortSignal.timeout(30000)});
    assert(res.ok,`Repair API returned ${res.status}`);return res.status===204?null:res.json();
  };
  const data=await call(`/app/installations/${env.JARVIS_REPAIR_INSTALLATION_ID}/access_tokens`,jwt,'POST',{repositories:[options.repo.split('/')[1]],permissions:{contents:'write'}});
  try {
    assert(data.repository_selection==='selected' && data.repositories?.length===1 && data.repositories[0].full_name===options.repo,'Repair token exceeded repository scope');
    assert(Object.entries(data.permissions).every(([k,v])=>k==='contents'&&v==='write'||k==='metadata'&&v==='read'),'Unexpected repair token permissions');
    return await writeRepair({...options,request:(path,method,body)=>{assert(path.startsWith(`/repos/${options.repo}/git/`),'Unexpected repair API path');return call(path,data.token,method,body);}});
  } finally { await call('/installation/token',data.token,'DELETE'); }
}
