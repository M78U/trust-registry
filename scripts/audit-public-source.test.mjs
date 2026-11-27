import test from "node:test";
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {mkdtempSync,writeFileSync,rmSync,mkdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {auditPublicSource} from "./audit-public-source.mjs";

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),"m78u-audit-test-"));
 t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const git=(...args)=>{
  const r=spawnSync("git",["-C",dir,...args],{encoding:"utf8",timeout:10000});
  assert.equal(r.status,0,r.stderr);return r.stdout.trim();
 };
 git("init","-b","main");git("config","user.name","Synthetic");git("config","user.email","fixture@example.invalid");
 const commit=()=>{git("add",".");git("commit","-m","fixture")};
 writeFileSync(join(dir,"README.md"),"synthetic public file\n");commit();
 return {dir,git,commit};
}
test("clean history is only a preflight result",t=>{
 const {dir}=fixture(t);const r=auditPublicSource(dir);
 assert.equal(r.status,"PREFLIGHT_NO_MARKERS_FOUND");assert.equal(r.publicVisibilityAuthorized,false);
 assert.equal(r.blobCount,1);assert.equal(r.findings.length,0);
});
test("deleted and branch-only blobs are inspected without revealing content",t=>{
 const {dir,git,commit}=fixture(t);
 const secret="gh"+"p_"+"x".repeat(36);
 writeFileSync(join(dir,"historical.txt"),secret);commit();
 rmSync(join(dir,"historical.txt"));commit();
 git("switch","-c","other");
 mkdirSync(join(dir,"private-ledger"));
 writeFileSync(join(dir,"private-ledger","record.json"),"{}");
 writeFileSync(join(dir,"binary.bin"),Buffer.from([0,255,1]));
 commit();git("switch","main");
 const r=auditPublicSource(dir);
 assert.equal(r.status,"REVIEW_REQUIRED");
 for(const reason of ["GITHUB_TOKEN_MARKER","PRIVATE_WORKSPACE_PATH","BINARY_BLOB_REVIEW"])assert.ok(r.findings.some(x=>x.reason===reason),reason);
 const output=JSON.stringify(r);
 assert.ok(!output.includes(secret));assert.ok(!output.includes("historical.txt"));assert.ok(!output.includes("private-ledger"));
 assert.equal(r.publicVisibilityAuthorized,false);
});
test("invalid repository and partial clone fail closed",t=>{
 const {dir,git}=fixture(t);
 const invalid=auditPublicSource(join(dir,"missing"));
 assert.equal(invalid.status,"INCOMPLETE");
 git("config","remote.origin.promisor","true");
 const partial=auditPublicSource(dir);
 assert.equal(partial.status,"INCOMPLETE");assert.equal(partial.error,"PARTIAL_CLONE");
});
