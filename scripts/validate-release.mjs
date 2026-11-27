// Explicit local/manual developer release acceptance. Never publishes.
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {parseModuleStream,collectLicenseEvidence} from "./dependency-license-evidence.mjs";

const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const tuf=join(root,"tools","tuf-client"), web=join(root,"web");
const opts=new Map();
for(const arg of process.argv.slice(2)){
 const i=arg.indexOf("=");
 if(i<1||!["--mode","--report-dir"].includes(arg.slice(0,i))||opts.has(arg.slice(0,i))||!arg.slice(i+1))throw Error("usage: node scripts/validate-release.mjs --mode=locked|lock-candidate|lock-only [--report-dir=NEW_DIR]");
 opts.set(arg.slice(0,i),arg.slice(i+1));
}
const mode=opts.get("--mode")??"locked";
if(!["locked","lock-candidate","lock-only"].includes(mode))throw Error("unsupported validation mode");
const reportDir=opts.has("--report-dir")?resolve(opts.get("--report-dir")):mkdtempSync(join(tmpdir(),"m78u-validation-report-"));
if(opts.has("--report-dir"))mkdirSync(reportDir,{mode:0o700});
const scratch=mkdtempSync(join(tmpdir(),"m78u-validation-"));
const report={schemaVersion:"1",kind:"LOCAL_DEVELOPER_VALIDATION",mode,startedAt:new Date().toISOString(),sourceRevision:null,sourceClean:false,stages:[],dependencyFiles:[],status:"FAILED",productionReleaseAuthorized:false,cloudflareDeployment:false,licenseReviewComplete:false,dependencyGraphEvidence:null};
const env={...process.env,GOWORK:"off",GOTOOLCHAIN:"local",GOFLAGS:"",GOSUMDB:"sum.golang.org",GOPRIVATE:"",GONOSUMDB:"",GONOPROXY:""};
const hash=data=>createHash("sha256").update(data).digest("hex");
const modules=[{name:"registry",dir:root},{name:"tuf-client",dir:tuf}];
const lockPaths=modules.flatMap(m=>["go.mod","go.sum"].map(name=>({module:m.name,name,path:join(m.dir,name)})));
const before=new Map(lockPaths.map(f=>[f.path,existsSync(f.path)?hash(readFileSync(f.path)):null]));
function command(label,exe,args,cwd,{failure=false,capture=false}={}){
 const start=Date.now();
 const run=spawnSync(exe,args,{cwd,env,encoding:"utf8",timeout:10*60*1000,maxBuffer:16*1024*1024,windowsHide:true});
 const ok=!run.error&&run.signal===null&&(failure?Number.isInteger(run.status)&&run.status!==0:run.status===0);
 report.stages.push({name:label,status:ok?"PASS":"FAIL",exitCode:run.status,signal:run.signal,durationMs:Date.now()-start,expectedFailure:failure});
 console.log("["+ (ok?"PASS":"FAIL")+"] "+label);
 if(!capture||!ok){if(run.stdout)process.stdout.write(run.stdout);if(run.stderr)process.stderr.write(run.stderr);}
 if(!ok)throw Error(label+": "+(run.error?.message??"unexpected exit status "+run.status));
 return run.stdout??"";
}
function check(label,fn){
 const start=Date.now();
 try{fn();report.stages.push({name:label,status:"PASS",durationMs:Date.now()-start});console.log("[PASS] "+label);}
 catch(err){report.stages.push({name:label,status:"FAIL",durationMs:Date.now()-start});throw err;}
}
function jsonCommand(label,exe,args,cwd,options={}){
 return JSON.parse(command(label,exe,args,cwd,{...options,capture:true}));
}
const git=(label,args)=>command(label,"git",args,root,{capture:true}).trim();
const suffix=process.platform==="win32"?".exe":"";
const bin=name=>join(scratch,name+suffix);
let failed=false;
try{
 check("Node runtime",()=>assert.ok(Number(process.versions.node.split(".")[0])>=20,"Node >=20 required"));
 report.sourceRevision=git("source revision",["rev-parse","HEAD"]);
 report.sourceClean=git("source status",["status","--porcelain","--untracked-files=normal"])==="";
 if(mode==="locked"&&!report.sourceClean)throw Error("locked validation requires clean checkout");
 command("Go runtime","go",["version"],root);
 if(mode==="locked")check("committed dependency locks",()=>{
  for(const f of lockPaths){
   assert.ok(existsSync(f.path),"missing "+f.module+"/"+f.name);
   const rel=f.module==="registry"?f.name:"tools/tuf-client/"+f.name;
   assert.equal(git("tracked lock "+rel,["ls-files","--error-unmatch",rel]),rel);
  }
 });
 // Resolve both module graphs before executing tests, so a main-module
 // test failure does not prevent collecting the TUF lock candidate.
 const graphs=[];
 let resolutionFailed=false;
 for(const m of modules){
  try{
   command(m.name+" dependency "+mode,"go",mode==="locked"?["mod","tidy","-diff"]:["mod","tidy"],m.dir);
   graphs.push({name:m.name,items:parseModuleStream(command(m.name+" selected module graph","go",["list","-m","-mod=readonly","-json","all"],m.dir,{capture:true}))});
  }catch(err){
   resolutionFailed=true;
   if(mode==="locked")throw err;
   console.error(m.name+" dependency resolution/evidence failed; continuing with other module");
  }
 }
 if(graphs.length){
  const evidence=collectLicenseEvidence(graphs,root,join(reportDir,"dependency-licenses"));
  report.dependencyGraphEvidence={graphs:graphs.map(g=>g.name),rows:evidence.modules.length,evidenceBytes:evidence.evidenceBytes,inventory:"dependency-licenses/inventory.json"};
 }
 if(resolutionFailed)throw Error("dependency resolution or graph collection failed");
 if(mode==="lock-only"){
  report.status="LOCK_CANDIDATE_RESOLVED_NOT_TESTED";
 }else{
 for(const m of modules){
  command(m.name+" module verify","go",["mod","verify"],m.dir);
  command(m.name+" vet","go",["vet","-mod=readonly","./..."],m.dir);
  command(m.name+" tests","go",["test","-mod=readonly","-count=1","-timeout=5m","./..."],m.dir);
  command(m.name+" build","go",["build","-mod=readonly","./..."],m.dir);
 }
 for(const [name,dir] of [["trust-registry",root],["tuf-publish",tuf],["tuf-fetch",tuf],["tuf-load",tuf]]){
  command("build CLI "+name,"go",["build","-mod=readonly","-trimpath","-o",bin(name),"./cmd/"+name],dir);
 }
 const registry=join(scratch,"inventory"), envelope=join(scratch,"empty.json"), evidence=join(scratch,"evidence"), dossier=join(scratch,"dossier.json");
 mkdirSync(evidence,{mode:0o700});
 const at=new Date(), expires=new Date(at.getTime()+60*60*1000);
 const trust=bin("trust-registry");
 jsonCommand("CLI inventory init",trust,["init","--registry",registry],scratch);
 jsonCommand("CLI inventory validate",trust,["validate","--registry",registry],scratch);
 jsonCommand("CLI snapshot build",trust,["snapshot","build","--registry",registry,"--sequence","1","--revision",report.sourceRevision,"--created-at",at.toISOString(),"--expires-at",expires.toISOString(),"--out",envelope],scratch);
 const verified=jsonCommand("CLI snapshot verify",trust,["snapshot","verify",envelope],scratch);
 check("CLI snapshot identity",()=>{assert.equal(verified.snapshotSHA256,hash(readFileSync(envelope)));assert.equal(verified.releaseAuthenticated,false);assert.equal(verified.trustStatus,"NOT_ESTABLISHED");});
 const pending=jsonCommand("CLI review plan",trust,["review","plan",envelope],scratch);
 writeFileSync(dossier,JSON.stringify(pending)+"\n",{mode:0o600});
 const blocked=jsonCommand("CLI empty inventory release blocked",trust,["review","check","--dossier",dossier,"--evidence",evidence,"--at",at.toISOString(),envelope],scratch,{failure:true});
 check("CLI release remains blocked",()=>assert.equal(blocked.status,"BLOCKED"));
 const invalid=join(scratch,"tampered.json");
 writeFileSync(invalid,Buffer.concat([readFileSync(envelope),Buffer.from("\n")]));
 command("CLI tampered snapshot rejected",trust,["snapshot","verify",invalid],scratch,{failure:true});
 for(const name of ["tuf-publish","tuf-fetch","tuf-load"])command("CLI missing arguments rejected "+name,bin(name),[],scratch,{failure:true});
 command("Public-source audit and dependency evidence tests",process.execPath,["--test","scripts/audit-public-source.test.mjs","scripts/dependency-license-evidence.test.mjs"],root);
 const tests=readdirSync(join(web,"scripts")).filter(n=>n.endsWith(".test.mjs")).sort();
 check("Explorer tests present",()=>assert.ok(tests.length>0));
 command("Explorer tests",process.execPath,["--test",...tests.map(n=>join("scripts",n))],web);
 command("Explorer build",process.execPath,["scripts/build.mjs"],web);
 check("Static release configuration",()=>{
  const c=JSON.parse(readFileSync(join(web,"wrangler.release.jsonc"),"utf8"));
  assert.deepEqual(Object.keys(c).sort(),["assets","compatibility_date","name","preview_urls","routes","workers_dev"]);
  assert.equal(c.workers_dev,false);assert.equal(c.preview_urls,false);
  assert.deepEqual(c.routes,[{pattern:"trust.m78u.com",custom_domain:true}]);
  assert.deepEqual(c.assets,{directory:"./release-dist",html_handling:"auto-trailing-slash",not_found_handling:"none",run_worker_first:false});
 });
 if(mode==="locked"){
  check("dependency locks unchanged",()=>{for(const f of lockPaths)assert.equal(hash(readFileSync(f.path)),before.get(f.path));});
  assert.equal(git("final revision",["rev-parse","HEAD"]),report.sourceRevision);
  assert.equal(git("final source status",["status","--porcelain","--untracked-files=normal"]),"");
 }
 report.status=mode==="locked"?"LOCKED_DEVELOPER_VALIDATION_PASSED":"LOCK_CANDIDATE_VALIDATED_NOT_COMMITTED";
 }
}catch(err){
 failed=true;report.error=String(err.message??err);console.error(report.error);
}finally{
 for(const f of lockPaths){
  const data=existsSync(f.path)?readFileSync(f.path):null;
  const after=data?hash(data):null;
  report.dependencyFiles.push({module:f.module,name:f.name,before:before.get(f.path),after,changed:after!==before.get(f.path)});
  if(mode!=="locked"&&data){
   const dir=join(reportDir,"lock-candidate",f.module);mkdirSync(dir,{recursive:true,mode:0o700});
   writeFileSync(join(dir,f.name),data,{mode:0o600});
  }
 }
 report.finishedAt=new Date().toISOString();
 writeFileSync(join(reportDir,"report.json"),JSON.stringify(report,null,2)+"\n",{mode:0o600});
 rmSync(scratch,{recursive:true,force:true});
 console.log("Validation report: "+join(reportDir,"report.json"));
}
if(failed)process.exitCode=1;
