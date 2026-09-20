import assert from 'node:assert/strict';
// A 502 can mean GitHub accepted a merge but timed out replying. Reconcile the
// actual PR and commit before retrying; never infer success from a request alone.
export async function confirmedMerge({request,repo,number,head,base,title,wait=ms=>new Promise(r=>setTimeout(r,ms))}) {
  const prefix=`/repos/${repo}`;
  const verify=async(pr)=>{
    assert(pr.merged && pr.head.sha===head && /^[a-f0-9]{40}$/.test(pr.merge_commit_sha),'Unexpected merged PR');
    const [commit,original,main]=await Promise.all([request(`${prefix}/git/commits/${pr.merge_commit_sha}`),request(`${prefix}/git/commits/${head}`),request(`${prefix}/git/ref/heads/main`)]);
    assert(commit.parents.length===1 && commit.parents[0].sha===base && commit.tree.sha===original.tree.sha,'Merged commit does not match the reviewed changes');
    assert(main.object.sha===pr.merge_commit_sha,'Main advanced; stop this release');
    return pr.merge_commit_sha;
  };
  for(let attempt=0;attempt<5;attempt++) {
    let error;
    try {
      await request(`${prefix}/pulls/${number}/merge`,'PUT',{sha:head,merge_method:'squash',commit_title:title||`chore(deps): maintain approved development packages (#${number})`});
    } catch(e) {
      if(!(e.status>=500||[405,409].includes(e.status)||['TypeError','TimeoutError'].includes(e.name)))throw e;
      error=e;
    }
    for(let poll=0;poll<4;poll++) {
      const pr=await request(`${prefix}/pulls/${number}`);
      assert(pr.head.sha===head,'PR changed; stop merge recovery');
      if(pr.merged)return verify(pr);
      assert(pr.state==='open','PR closed without a merge');
      assert((await request(`${prefix}/git/ref/heads/main`)).object.sha===base,'Main changed; fresh CI required');
      await wait(15000);
    }
    if(attempt===4)throw error||Error('GitHub has not confirmed the merge after bounded recovery');
  }
}
