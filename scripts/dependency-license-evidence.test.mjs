import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {createHash} from "node:crypto";
import {parseModuleStream,collectLicenseEvidence} from "./dependency-license-evidence.mjs";

test("module stream parsing and malformed input",()=>{
 const items=[{Path:"example.org/root",Main:true},{Path:"example.org/dep",Version:"v1.0.0"}];
 assert.deepEqual(parseModuleStream(items.map(m=>JSON.stringify(m,null,2)).join("\n")+"\n"),items);
 assert.throws(()=>parseModuleStream(""));
 assert.throws(()=>parseModuleStream('{"Main":true}'));
});

test("license evidence is deduplicated and never grants approval",t=>{
 const dir=mkdtempSync(join(tmpdir(),"m78u-license-test-"));
 t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const dep=join(dir,"dep"),empty=join(dir,"empty");mkdirSync(dep);mkdirSync(empty);
 writeFileSync(join(dep,"LICENSE"),"synthetic license\n");
 writeFileSync(join(dep,"NOTICE.txt"),"synthetic notice\n");
 writeFileSync(join(dep,"README.md"),"not a license");
 const ext={Path:"example.org/dep",Version:"v1.0.0",Dir:dep};
 const graphs=[{name:"registry",items:[{Path:"github.com/M78U/trust-registry",Main:true},ext,
  {Path:"example.org/missing",Version:"v1.0.0"},{Path:"example.org/empty",Version:"v1.0.0",Dir:empty}]},
  {name:"tuf-client",items:[ext,{Path:"github.com/M78U/trust-registry",Replace:{Dir:dir}},
   {Path:"example.org/replaced",Replace:{Dir:dir}}]}];
 const out=join(dir,"report");
 const r=collectLicenseEvidence(graphs,dir,out);
 assert.equal(r.licenseReviewComplete,false);assert.equal(r.publicVisibilityAuthorized,false);
 const rows=r.modules.filter(m=>m.path===ext.Path);
 assert.equal(rows.length,2);assert.equal(rows[0].files.length,2);assert.deepEqual(rows[0].files,rows[1].files);
 for(const file of rows[0].files){
  const bytes=readFileSync(join(out,file.evidenceFile));
  assert.equal(createHash("sha256").update(bytes).digest("hex"),file.sha256);
 }
 assert.equal(r.evidenceBytes,Buffer.byteLength("synthetic license\nsynthetic notice\n"));
 for(const status of ["SOURCE_NOT_AVAILABLE_REVIEW","NO_TOP_LEVEL_LICENSE_FILE_REVIEW","PROJECT_LOCAL_REPLACEMENT","UNEXPECTED_REPLACEMENT_REVIEW"])
  assert.ok(r.modules.some(m=>m.status===status),status);
 assert.ok(!JSON.stringify(r).includes(dir));
 assert.deepEqual(JSON.parse(readFileSync(join(out,"inventory.json"),"utf8")),r);
});
