import {createHash} from 'node:crypto';
import {lstatSync, readdirSync, readFileSync, realpathSync, mkdirSync, writeFileSync} from 'node:fs';
import {resolve, dirname, relative, isAbsolute, sep, join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const digest = b => createHash('sha256').update(b).digest('hex');
const notice = /^(?:licen[cs]e|copying|copyright|notice|patents|unlicense|third[-_ ]party[-_ ]notices)(?:[._-].+)?$/i;
const inside = (root, path) => {const r = relative(root, path); return r === '' || (!isAbsolute(r) && r !== '..' && !r.startsWith('..'+sep));};
const MAX_PACKAGES=10000, MAX_DIRS=10000, MAX_BYTES=32*1024*1024, MAX_FILE=512*1024;
export function parsePackages(raw){
  const rows=raw.trim().split(/\n(?=\{)/).filter(Boolean).map(JSON.parse);
  if(!rows.length || rows.length>MAX_PACKAGES || rows.some(p=>!p.ImportPath||p.Error||p.Incomplete||!p.Dir&&p.ImportPath!=='unsafe'))throw Error('incomplete package graph');
  return rows;
}
// Collect top-level and ancestor notices of selected package directories only.
// Not an SPDX classifier; source headers and embedded assets still require review.
export function collectPackages(packages, goroot, project, out, build){
  goroot=realpathSync(goroot); project=realpathSync(project);
  if(packages.length>MAX_PACKAGES)throw Error('package limit');
  const groups=new Map();
  for(const p of packages){
    if(p.ImportPath==='unsafe'&&!p.Dir)continue;
    if(p.Module?.Main){if(!inside(project,realpathSync(p.Dir)))throw Error('unexpected main package');continue;}
    if(p.Module?.Replace)throw Error('unexpected replacement: '+p.ImportPath);
    const m=p.Module;
    if(!p.Standard&&(!m?.Path||!m.Version||!m.Dir))throw Error('missing package module identity: '+p.ImportPath);
    const root=p.Standard?goroot:realpathSync(m.Dir),dir=realpathSync(p.Dir),id=p.Standard?'go-toolchain@'+build.GOVERSION:m.Path+'@'+m.Version;
    if(!inside(p.Standard?join(goroot,'src'):root,dir))throw Error('package outside source root');
    let g=groups.get(id);
    if(!g){g={root,dirs:new Set(),packages:new Set(),files:[],warnings:[]};groups.set(id,g);}
    if(g.root!==root)throw Error('inconsistent source root');
    g.packages.add(p.ImportPath);
    for(let d=dir;;d=dirname(d)){g.dirs.add(d);if(d===root)break;}
  }
  if(![...groups.keys()].some(k=>k.startsWith('go-toolchain@')))throw Error('missing standard library graph');
  mkdirSync(out,{mode:0o700});
  let total=0,dirs=0;
  const report={schemaVersion:'1',kind:'CLI_PACKAGE_LICENSE_EVIDENCE',build,licenseReviewComplete:false,distributionAuthorized:false,modules:[]};
  for(const [id,g] of [...groups].sort(([a],[b])=>a.localeCompare(b))){
    for(const d of [...g.dirs].sort()){
      if(++dirs>MAX_DIRS)throw Error('directory limit');
      const names=readdirSync(d).filter(n=>notice.test(n)).sort();
      if(names.length>32)throw Error('notice file count limit');
      for(const name of names){
        const file=join(d,name),path=relative(g.root,file).split(sep).join('/'),st=lstatSync(file);
        if(!st.isFile()||st.size>MAX_FILE){g.warnings.push({path,status:'MANUAL_REVIEW'});continue;}
        const bytes=readFileSync(file);
        if(bytes.length!==st.size||total+bytes.length>MAX_BYTES)throw Error('evidence byte limit');
        total+=bytes.length;
        const evidenceFile=digest(id+'\0'+path)+'.txt';
        writeFileSync(join(out,evidenceFile),bytes,{flag:'wx',mode:0o600});
        g.files.push({path,sha256:digest(bytes),bytes:bytes.length,evidenceFile});
      }
    }
    if(!g.files.length)g.warnings.push({status:'NO_NOTICE_FOUND_REVIEW'});
    report.modules.push({id,packages:[...g.packages].sort(),files:g.files,warnings:g.warnings});
  }
  report.evidenceBytes=total;
  writeFileSync(join(out,'inventory.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  return report;
}
function main(){
  const root=realpathSync(resolve(dirname(fileURLToPath(import.meta.url)),'..'));
  const args=process.argv.slice(2);
  if(args.length!==1||!args[0].startsWith('--out=')||!args[0].slice(6))throw Error('usage: node scripts/cli-license-evidence.mjs --out=NEW_PRIVATE_DIR');
  const out=resolve(args[0].slice(6));
  if(inside(root,join(realpathSync(dirname(out)),out.split(sep).at(-1))))throw Error('output must be outside checkout');
  const env={...process.env,GOWORK:'off',GOFLAGS:'',GOTOOLCHAIN:'local',CGO_ENABLED:'0',GOPRIVATE:'',GONOSUMDB:'',GONOPROXY:'',GOSUMDB:'sum.golang.org'};
  const run=(cmd,a)=>execFileSync(cmd,a,{cwd:root,env,encoding:'utf8',maxBuffer:32*1024*1024,timeout:180000});
  if(run('git',['status','--porcelain']))throw Error('clean checkout required');
  const revision=run('git',['rev-parse','HEAD']).trim(),locks=['go.mod','go.sum'].map(p=>digest(readFileSync(join(root,p))));
  const info=JSON.parse(run('go',['env','-json','GOOS','GOARCH','GOROOT','GOVERSION']));
  const packages=parsePackages(run('go',['list','-mod=readonly','-deps','-json','./cmd/trust-registry']));
  run('go',['mod','verify']);
  if(run('git',['status','--porcelain'])||run('git',['rev-parse','HEAD']).trim()!==revision||locks.some((h,i)=>h!==digest(readFileSync(join(root,['go.mod','go.sum'][i])))))throw Error('checkout changed during collection');
  const {GOOS,GOARCH,GOVERSION}=info;
  const report=collectPackages(packages,info.GOROOT,root,out,{GOOS,GOARCH,GOVERSION,CGO_ENABLED:'0',revision,target:'./cmd/trust-registry',lockSHA256:{goMod:locks[0],goSum:locks[1]}});
  console.log('Collected '+report.modules.length+' package groups; review required.');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try{main();}catch(e){console.error(e.message);process.exitCode=1;}
