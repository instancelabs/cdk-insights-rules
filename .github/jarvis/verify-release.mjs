import assert from 'node:assert/strict';
const {GITHUB_REPOSITORY:repo,GH_TOKEN:token,RELEASE_SHA:sha}=process.env;
assert(/^[a-f0-9]{40}$/.test(sha),'Immutable release SHA is required');
const response=await fetch(`https://api.github.com/repos/${repo}/git/ref/heads/main`,{headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json'},redirect:'error',signal:AbortSignal.timeout(20000)});
assert(response.ok,'Cannot verify current main');
assert((await response.json()).object.sha===sha,'Main changed since validation; stop this release and assess the newer commit');
console.log('Release is pinned to current main: '+sha);
