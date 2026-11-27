// Advisory local preflight. Never invokes repository code, network, or uploads.
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";

const LIMIT={trees:2000,entries:200000,blobs:10000,blobBytes:2*1024*1024,totalBytes:128*1024*1024,findings:10000};
const sha=b=>createHash("sha256").update(b).digest("hex");
const oid=/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const patterns=[
 ["PRIVATE_KEY_MARKER",/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/],
 ["GITHUB_TOKEN_MARKER",/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/],
 ["AWS_ACCESS_ID_MARKER",/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
 ["URL_CREDENTIAL_MARKER",/https?:\/\/[^\s/@:]+:[^\s/@]+@/],
 ["LFS_POINTER",/^version https:\/\/git-lfs.github.com\/spec\/v1\r?$/m]
];
function pathReason(p){
 if(/(?:^|\/)(?:\.private|private-(?:ledger|evidence|acquisition|review|keys|release)|local-registry|local-state|tuf-state|\.release-audit|\.release-validation|release-dist|\.wrangler)(?:\/|$)/i.test(p))return "PRIVATE_WORKSPACE_PATH";
 if(/(?:^|\/)(?:\.env(?:\..*)?|\.dev\.vars(?:\..*)?|id_(?:rsa|ed25519|ecdsa))(?:$|\/)/i.test(p)||/\.(?:key|pem|p12|pfx|jks|keystore|pkcs8|der|cer|crt|crl|ocsp|zip|7z|tar|gz|pdf|docx)$/i.test(p))return "SENSITIVE_OR_BINARY_PATH";
 return null;
}
export function auditPublicSource(repo){
 const report={schemaVersion:"1",kind:"LOCAL_REACHABLE_HISTORY_PREFLIGHT",status:"INCOMPLETE",refCount:0,treeCount:0,entryCount:0,blobCount:0,bytesInspected:0,binaryBlobs:0,oversizeBlobs:0,findings:[],publicVisibilityAuthorized:false};
 const env={...process.env,GIT_NO_REPLACE_OBJECTS:"1",GIT_NO_LAZY_FETCH:"1",GIT_TERMINAL_PROMPT:"0",GIT_OPTIONAL_LOCKS:"0"};
 // Ignore ambient repository selection and object injection.
 for(const k of ["GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_INDEX_FILE","GIT_OBJECT_DIRECTORY","GIT_ALTERNATE_OBJECT_DIRECTORIES","GIT_NAMESPACE","GIT_CONFIG_COUNT","GIT_CONFIG_PARAMETERS"])delete env[k];
 const git=(args,allowMissing=false)=>{
  const r=spawnSync("git",["-C",repo,...args],{env,timeout:30000,maxBuffer:16*1024*1024,windowsHide:true});
  if(allowMissing&&!r.error&&r.status===1)return Buffer.alloc(0);
  if(r.error||r.status!==0)throw Error("GIT_COMMAND_FAILED");
  return r.stdout;
 };
 const require=(ok,code)=>{if(!ok)throw Error(code)};
 const add=(reason,object,pathSHA256)=>{
  require(report.findings.length<LIMIT.findings,"FINDING_LIMIT");
  report.findings.push({reason,object,...(pathSHA256?{pathSHA256}:{})});
 };
 try{
  require(git(["rev-parse","--is-shallow-repository"]).toString().trim()==="false","SHALLOW_REPOSITORY");
  require(!git(["config","--get-regexp","^(extensions\\.partialclone|remote\\..*\\.promisor)$"],true).length,"PARTIAL_CLONE");
  const refs=()=>git(["for-each-ref","--format=%(objectname) %(refname)"]);
  const before=refs();
  report.refsSHA256=sha(before);report.refCount=before.toString().split("\n").filter(Boolean).length;
  require(report.refCount>0,"NO_REFS");
  report.head=git(["rev-parse","HEAD"]).toString().trim();
  require(oid.test(report.head),"INVALID_HEAD");
  const trees=[...new Set(git(["log","--all","--format=%T","--no-show-signature"]).toString().split(/\s+/).filter(Boolean))].sort();
  require(trees.length>0&&trees.length<=LIMIT.trees&&trees.every(t=>oid.test(t)),"TREE_LIMIT_OR_INVALID");
  const blobs=new Set(),seenPaths=new Set();
  for(const tree of trees){
   report.treeCount++;
   const raw=git(["ls-tree","-r","-z",tree]);
   for(const entry of raw.toString("utf8").split("\0").filter(Boolean)){
    require(++report.entryCount<=LIMIT.entries,"ENTRY_LIMIT");
    const i=entry.indexOf("\t"),fields=entry.slice(0,i).split(" "),path=entry.slice(i+1);
    require(i>0&&fields.length===3&&oid.test(fields[2]),"INVALID_TREE_ENTRY");
    const [mode,type,object]=fields;
    const pathSHA256=sha(path),key=object+":"+pathSHA256;
    if(!seenPaths.has(key)){
     seenPaths.add(key);
     const reason=pathReason(path);
     if(reason)add(reason,object,pathSHA256);
     if(mode==="120000")add("SYMLINK_REVIEW",object,pathSHA256);
     if(type==="commit")add("SUBMODULE_REVIEW",object,pathSHA256);
     if(path.includes("\uFFFD"))add("NON_UTF8_PATH_REVIEW",object,pathSHA256);
    }
    if(type==="blob")blobs.add(object);
    require(blobs.size<=LIMIT.blobs,"BLOB_LIMIT");
   }
  }
  for(const object of [...blobs].sort()){
   const size=Number(git(["cat-file","-s",object]).toString().trim());
   require(Number.isSafeInteger(size)&&size>=0,"INVALID_BLOB_SIZE");
   if(size>LIMIT.blobBytes){report.oversizeBlobs++;add("OVERSIZE_BLOB_REVIEW",object);continue}
   require(report.bytesInspected+size<=LIMIT.totalBytes,"TOTAL_BYTE_LIMIT");
   const raw=git(["cat-file","blob",object]);
   require(raw.length===size,"BLOB_SIZE_CHANGED");
   report.blobCount++;report.bytesInspected+=size;
   const text=raw.toString("utf8");
   if(raw.includes(0)||!Buffer.from(text,"utf8").equals(raw)){report.binaryBlobs++;add("BINARY_BLOB_REVIEW",object);continue}
   for(const [reason,pattern] of patterns)if(pattern.test(text))add(reason,object);
  }
  require(before.equals(refs())&&report.head===git(["rev-parse","HEAD"]).toString().trim(),"REFS_CHANGED");
  report.status=report.findings.length?"REVIEW_REQUIRED":"PREFLIGHT_NO_MARKERS_FOUND";
 }catch(err){
  const code=String(err.message);
  report.error=/^[A-Z_]+$/.test(code)?code:"PREFLIGHT_FAILED";
 }
 return report;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args=process.argv.slice(2);
 if(args.length!==1||!args[0].startsWith("--repo=")||args[0].length===7){
  console.error("usage: node scripts/audit-public-source.mjs --repo=LOCAL_CLONE");process.exitCode=2;
 }else{
  const r=auditPublicSource(resolve(args[0].slice(7)));
  console.log(JSON.stringify(r,null,2));
  process.exitCode=r.status==="INCOMPLETE"?2:r.findings.length?1:0;
 }
}
