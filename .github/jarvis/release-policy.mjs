import assert from 'node:assert/strict';
import {isDeepStrictEqual as equal} from 'node:util';
const semver=x=>{const m=/^(\^|~)?(\d+)\.(\d+)\.(\d+)$/.exec(x??'');assert(m,'Only stable simple semver is eligible');return [m[1]||'',...m.slice(2).map(Number)];};
export function stableUpgrade(a,b,{allowZeroPatch=false}={}){
 const [range,major,minor,patch]=semver(a),[r,M,m,p]=semver(b);
 assert(range===r&&major===M&&(m>minor||m===minor&&p>patch)&&(major>0||allowZeroPatch&&minor===m),'Major, prerelease, downgrade or incompatible zero-major changes require review');
}
export function registryPackage(path,p){
 assert(path.startsWith('node_modules/')&&!path.split('/').some(x=>x==='..'||x==='.')&&!p.link,'Only registry package paths are allowed');
 const name=path.split('node_modules/').at(-1);assert(/^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/i.test(name),'Unexpected package path');
 if(p.name!==undefined)assert.equal(p.name,name,'Aliases require review');
 const u=new URL(p.resolved);assert(u.protocol==='https:'&&u.hostname==='registry.npmjs.org'&&!u.username&&!u.password&&!u.port&&!u.search&&!u.hash,'Only npm registry tarballs are allowed');
 assert(decodeURI(u.pathname)===`/${name}/-/${name.split('/').at(-1)}-${p.version}.tgz`,'Tarball identity must match the package and version');
 assert(/^sha512-[A-Za-z0-9+/=]+$/.test(p.integrity),'Package integrity is required');
}
function lockShape(before,after,a,b){
 assert(a.lockfileVersion>=2&&a.lockfileVersion===b.lockfileVersion,'Unsupported lockfile format');
 const x={...a},y={...b};delete x.packages;delete y.packages;assert(equal(x,y),'Unrelated lockfile metadata changed');
 const root={...a.packages?.['']};for(const k of ['dependencies','devDependencies']){if(after[k]!==undefined)root[k]=after[k];else delete root[k];}
 assert(equal(root,b.packages?.['']),'Root lockfile metadata or dependency declarations differ');
 for(const k of ['dependencies','devDependencies'])assert(equal(b.packages?.['']?.[k],after[k]),'Manifest and lockfile disagree');
}
export function lockOnlyPolicy(before,after,a,b,files,{ownerRequested=false}={}){
 assert(equal(before,after)&&files.length===1&&files[0].filename==='package-lock.json'&&files[0].status==='modified','Expected a lockfile-only update');lockShape(before,after,a,b);
 const changes=[];
 for(const path of new Set([...Object.keys(a.packages||{}),...Object.keys(b.packages||{})])){
  if(!path||equal(a.packages[path],b.packages[path]))continue;
  const old=a.packages[path],next=b.packages[path];assert(old&&next,'Adding or removing transitive packages needs direct-dependency review');
  if(!ownerRequested)assert(old.dev===true&&next.dev===true,'Runtime lockfile update needs an owner-requested release');
  stableUpgrade(old.version,next.version,{allowZeroPatch:ownerRequested});registryPackage(path,next);
  const x={...old},y={...next};for(const k of ['version','resolved','integrity']){delete x[k];delete y[k];}
  assert(equal(x,y),'Transitive scripts, flags or dependency edges changed');changes.push(path.split('node_modules/').at(-1));
 }
 assert(changes.length>0&&changes.length<=20,'Expected 1–20 bounded transitive updates');return [...new Set(changes)];
}
export function ownerDependencyPolicy(before,after,a,b,files){
 assert(files.length>0&&files.length<=2&&files.every(x=>['package.json','package-lock.json'].includes(x.filename)&&x.status==='modified'),'Only existing root npm manifests may change');
 if(equal(before,after))return lockOnlyPolicy(before,after,a,b,files,{ownerRequested:true});
 const x=structuredClone(before),y=structuredClone(after);for(const k of ['dependencies','devDependencies']){delete x[k];delete y[k];}
 assert(equal(x,y),'Scripts, overrides, package metadata and optional/peer declarations require a separate review');
 const changes=[];for(const k of ['dependencies','devDependencies']){
  const old=before[k]||{},next=after[k]||{};assert(equal(Object.keys(old).sort(),Object.keys(next).sort()),'Adding/removing dependencies requires review');
  for(const name of Object.keys(old))if(old[name]!==next[name]){stableUpgrade(old[name],next[name],{allowZeroPatch:true});changes.push(name);}
 }
 assert(changes.length>0&&changes.length<=20,'Expected 1–20 dependency upgrades');lockShape(before,after,a,b);
 let changed=0;for(const path of new Set([...Object.keys(a.packages||{}),...Object.keys(b.packages||{})])){
  if(!path||equal(a.packages[path],b.packages[path]))continue;
  assert(++changed<=1500,'Dependency tree change too large');const old=a.packages[path],next=b.packages[path];
  if(next)registryPackage(path,next);
  if(old&&next){
   assert(old.hasInstallScript===next.hasInstallScript,'Installation script capability changed');
   if(old.version!==next.version)stableUpgrade(old.version,next.version,{allowZeroPatch:true});
   else{const x={...old},y={...next};for(const k of ['dev','peer','optional','devOptional']){delete x[k];delete y[k];}assert(equal(x,y),'Same-version package contents changed');}
  }
 }
 return changes;
}
export function sourceRepairPolicy(pr,files){
 assert(pr.user?.login==='instance-labs-jarvis-repair[bot]'&&pr.user?.id===331706345&&pr.head?.ref?.startsWith('jarvis/fix-'),'Only source repairs created by the Jarvis Repair App are eligible');
 assert(pr.body?.includes('<!-- jarvis-owner-repair:v1 -->'),'Owner repair provenance is missing');
 assert(files.length>0&&files.length<=12,'Expected 1–12 source repair files');let size=0;
 for(const f of files){
  const p=f.filename;assert(f.status==='modified'&&!f.previous_filename,'Only modified existing source files are eligible');
  assert(typeof p==='string'&&p.length<250&&/^[A-Za-z0-9_./@() -]+$/.test(p)&&!p.startsWith('/')&&!p.split('/').some(x=>x===''||x==='.'||x==='..'),'Invalid source path');
  assert(!/(^|\/)(\.[^/]+|AGENTS\.md|CLAUDE\.md|SKILL\.md|Dockerfile|docker-compose[^/]*|cdk\.json|infra|infrastructure|bin|lib|credentials[^/]*|secrets?[^/]*)(\/|$)/i.test(p),'Workflow, credentials, instructions and infrastructure require operator review');
  assert(/\.(ts|tsx|js|jsx|mjs|cjs|json|css|scss|md|swift)$/.test(p),'Unsupported source type');
  assert(!/(^|\/)(package(?:-lock)?\.json)$/.test(p),'Dependency manifests must use the dependency release policy');
  assert(typeof f.patch==='string'&&f.patch.length>0,'Full reviewable diff is required');size+=f.patch.length;
 }
 assert(size<=350000,'Repair diff is too large');return files.map(f=>f.filename);
}
export function ownerRequestPolicy(event,actor,actorId,expectedSha,pr){
 assert(event==='workflow_dispatch','Owner release requests must be explicitly dispatched');
 assert((actor==='TheLeePriest'&&String(actorId)==='24657363')||(actor==='instance-labs-jarvis-repair[bot]'&&String(actorId)==='331706345'),'Only Lee or the owner-authenticated Jarvis App may request a release');
 assert(/^[a-f0-9]{40}$/.test(expectedSha||'')&&pr.head.sha===expectedSha,'Release request must pin the current PR commit');
}
