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
 // Exercise the current source intake CLI, not only legacy inventory commands.
 // Use an empty private archive directory and explicit invalid selections.
 // No successful or attempted online acquisition belongs in this validation.
 const archive=join(scratch,"private-acquisitions");
 mkdirSync(archive,{mode:0o700});
 const coverage=jsonCommand("CLI offline CA acquisition coverage",trust,["sources","acquisition-coverage","--registry",registry],scratch);
 check("CLI acquisition coverage boundaries",()=>{
  assert.equal(coverage.schemaVersion,"1");
  assert.deepEqual(coverage.inventory,{certificates:0,provenanceRecords:0});
  assert.equal(coverage.counts.listingRows,coverage.tasks.length);
  assert.equal(coverage.counts.exactFingerprintRows,coverage.tasks.filter(t=>t.publishedSHA256!==undefined).length);
  assert.equal(coverage.counts.missingInventoryRows,coverage.counts.exactFingerprintRows);
  assert.equal(coverage.counts.noExactFingerprintRows+coverage.counts.exactFingerprintRows,coverage.counts.listingRows);
  assert.equal(coverage.counts.matchingInventoryRows,0);
  assert.equal(coverage.counts.matchingSourceAssertionRows,0);
  assert.equal(coverage.archiveCoverage,undefined);
  assert.equal(coverage.sourceAuthentication,"NOT_ESTABLISHED");
  assert.equal(coverage.trustStatus,"NOT_ESTABLISHED");
  assert.equal(coverage.releaseAuthenticated,false);
  for(const t of coverage.tasks){
   assert.equal(t.archiveStatus,"NOT_CHECKED");
   assert.equal(t.redistributionStatus,"NOT_REVIEWED");
  }
  assert.equal(Object.values(coverage.routeCounts).reduce((a,b)=>a+b,0),coverage.tasks.length);
  for(const id of ["uca-global-g2","uca-sm2","unitrust-global-r3"]){
   const row=coverage.tasks.find(t=>t.authority==="SHECA"&&t.listingId===id);
   assert.ok(row&&row.acquisitionRoute==="PINNED_ENDPOINT_ARCHIVE"&&/^[a-f0-9]{64}$/.test(row.publishedSHA256?.fingerprint??""),id);
  }
 });
 command("Maintainer Python runtime","python3",["-c","import sys; assert sys.version_info >= (3, 11)"],root);
 command("Maintainer Python regression suite","python3",["-B","-m","unittest","discover","-s","scripts","-p","test_*.py","-v"],root);
 command("Maintainer tagged CLI tests","go",["test","-tags","maintainer","-mod=readonly","-count=1","./cmd/trust-registry","./pkg/sources"],root);
 command("Build separate maintainer CLI","go",["build","-tags","maintainer","-mod=readonly","-trimpath","-o",bin("trust-registry-maintainer"),"./cmd/trust-registry"],root);
 command("Maintainer CLI source list",bin("trust-registry-maintainer"),["sources","monitor-list"],scratch);
 command("Consumer CLI monitor commands excluded",trust,["sources","monitor-list"],scratch,{failure:true});
 command("CLI technical coverage without explicit pins rejected",trust,["sources","acquisition-coverage","--registry",registry,"--technical"],scratch,{failure:true});
 command("CLI unpinned archive directory rejected",trust,["sources","acquisition-coverage","--registry",registry,"--archive",archive],scratch,{failure:true});
 command("CLI missing pinned archive rejected",trust,["sources","acquisition-coverage","--registry",registry,"--archive",archive,"--archive-pin","uca-global-g2="+"0".repeat(64),"--technical"],scratch,{failure:true});
 // A legacy-only selection is rejected at batch preflight. Use a
 // nonexistent archive directory as an extra safeguard against networking
 // even if selection validation regresses in a future implementation.
 command("CLI legacy-only acquisition batch rejected",trust,["sources","archive-fetch-batch","--archive",join(scratch,"not-created"),"--id","uca-root-g2"],scratch,{failure:true});
 command("CLI duplicate acquisition batch rejected",trust,["sources","archive-fetch-batch","--archive",join(scratch,"not-created"),"--id","uca-global-g2","--id","uca-global-g2"],scratch,{failure:true});
 command("CLI unpinned batch import rejected",trust,["sources","archive-import-batch","--registry",registry,"--archive",archive],scratch,{failure:true});
 command("CLI missing batch archive rejected",trust,["sources","archive-import-batch","--registry",registry,"--archive",archive,"--archive-pin","uca-global-g2="+"0".repeat(64)],scratch,{failure:true});
 const invalidOriginal=join(scratch,"invalid-original.cer");
 writeFileSync(invalidOriginal,"not a certificate",{mode:0o600});
 command("CLI invalid local original rejected",trust,["sources","archive-local","--archive",archive,"--id","uca-global-g2","--recorded-at",at.toISOString(),invalidOriginal],scratch,{failure:true});
 const finalInventory=jsonCommand("CLI candidate inventory after negative intake cases",trust,["validate","--registry",registry],scratch);
 check("CLI rejected intake leaves no candidate or archive",()=>{
  assert.deepEqual(finalInventory,{certificates:0,provenanceRecords:0});
  assert.deepEqual(readdirSync(archive),[]);
 });

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
