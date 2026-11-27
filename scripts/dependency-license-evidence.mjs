import {createHash} from "node:crypto";
import {lstatSync,readdirSync,readFileSync,mkdirSync,writeFileSync,realpathSync} from "node:fs";
import {join,resolve} from "node:path";

const hash=b=>createHash("sha256").update(b).digest("hex");
const MAX_MODULES=2000,MAX_FILES=32,MAX_FILE_BYTES=512*1024,MAX_TOTAL_BYTES=32*1024*1024;
const licenseName=/^(?:licen[cs]e|copying|copyright|notice|unlicense|third[-_ ]party[-_ ]notices)(?:[._-].+)?$/i;

// go list -m -json all emits a stream of pretty-printed JSON objects.
export function parseModuleStream(raw){
 const items=raw.trim().split(/\n(?=\{)/).filter(Boolean).map(s=>JSON.parse(s));
 if(!items.length||items.length>MAX_MODULES||items.some(m=>!m||typeof m.Path!=="string"||!m.Path))throw Error("invalid or oversized module graph");
 return items;
}

// Evidence, not SPDX classification or a legal determination. No source
// download, shell execution, absolute cache paths or automatic approval.
export function collectLicenseEvidence(graphs,repositoryRoot,output){
 mkdirSync(output,{mode:0o700});
 const report={schemaVersion:"1",kind:"DEPENDENCY_LICENSE_EVIDENCE",licenseReviewComplete:false,publicVisibilityAuthorized:false,modules:[]};
 let total=0;
 const copied=new Map();
 const root=realpathSync(repositoryRoot);
 for(const {name,items} of graphs){
  if(items.length>MAX_MODULES)throw Error("module graph limit");
  for(const m of [...items].sort((a,b)=>a.Path.localeCompare(b.Path))){
   const row={graph:name,path:m.Path,version:m.Version??null,indirect:!!m.Indirect,files:[],status:"REVIEW_REQUIRED"};
   report.modules.push(row);
   if(m.Error)throw Error("module graph contains resolution error");
   if(m.Main){row.status="PROJECT_SOURCE";continue}
   if(m.Replace){
    // The only intended local replacement is the Registry root module
    // consumed by the isolated TUF module.
    if(m.Path==="github.com/M78U/trust-registry"&&!m.Replace.Version&&m.Replace.Dir&&realpathSync(m.Replace.Dir)===root){
     row.status="PROJECT_LOCAL_REPLACEMENT";continue;
    }
    row.status="UNEXPECTED_REPLACEMENT_REVIEW";continue;
   }
   if(!m.Version||!m.Dir){row.status="SOURCE_NOT_AVAILABLE_REVIEW";continue}
   const id=m.Path+"@"+m.Version;
   if(copied.has(id)){
    const old=copied.get(id);
    if(realpathSync(m.Dir)!==old.dir)throw Error("same module version has inconsistent source location");
    row.files=old.files;row.status=old.status;continue;
   }
   const dir=realpathSync(m.Dir);
   const names=readdirSync(dir).filter(n=>licenseName.test(n)).sort();
   if(names.length>MAX_FILES)throw Error("license file count limit");
   for(const name of names){
    const file=join(dir,name),st=lstatSync(file);
    if(!st.isFile()||st.size>MAX_FILE_BYTES){row.status="LICENSE_FILE_MANUAL_REVIEW";continue}
    const raw=readFileSync(file);
    if(raw.length!==st.size||raw.length>MAX_FILE_BYTES||total+raw.length>MAX_TOTAL_BYTES)throw Error("license evidence byte limit");
    total+=raw.length;
    const digest=hash(raw),filename=hash(id+"\0"+name)+".txt";
    writeFileSync(join(output,filename),raw,{flag:"wx",mode:0o600});
    row.files.push({name,sha256:digest,bytes:raw.length,evidenceFile:filename});
   }
   if(!row.files.length&&row.status==="REVIEW_REQUIRED")row.status="NO_TOP_LEVEL_LICENSE_FILE_REVIEW";
   copied.set(id,{dir,files:row.files,status:row.status});
  }
 }
 report.evidenceBytes=total;
 writeFileSync(join(output,"inventory.json"),JSON.stringify(report,null,2)+"\n",{flag:"wx",mode:0o600});
 return report;
}
