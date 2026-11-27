import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {project,searchRows} from "./projection.mjs";
const load=async name=>JSON.parse(await readFile(new URL("../../pkg/sources/"+name,import.meta.url),"utf8"));
const sheca=await load("sheca.json"),satl=await load("satl.json"),endpoints=await load("sheca-endpoints.json"),multiCA=await load("multi-ca.json");
test("selected source leads, not certificate trust",()=>{
 const d=project(sheca,satl,endpoints,multiCA);
 assert.equal(d.certificates.length,32);assert.equal(d.program.length,7);
 assert.equal(d.certificates.filter(r=>r.sha256Lead).length,8);
 assert.equal(d.certificates.filter(r=>r.endpointLocated).length,11);
 assert.equal(d.policies.reduce((n,p)=>n+p.anchors,0),0);
 assert.equal(d.releaseAuthenticated,false);
 assert.equal(searchRows(d,"UCA Root SM2","ROOT","SM2_RESEARCH","LISTED").length,1);
 assert.equal(searchRows(d,"d066fbe23ac1","","","").length,1);
 assert.equal(searchRows(d,"","INTERMEDIATE","","DISUSE").length,3);
});
test("projection ignores unknown/private payloads and rejects invalid evidence",()=>{
 const s=structuredClone(sheca);s.entries[0].der="secret";s.entries[0].privateKey="secret";
 const d=project(s,satl,endpoints,multiCA);assert.equal(JSON.stringify(d).includes("secret"),false);
 const e=structuredClone(endpoints);e[1].publishedSHA256.sourceURL="javascript:alert(1)";
 assert.throws(()=>project(sheca,satl,e,multiCA));
 const p=structuredClone(satl);p.entries[0].candidateListingId="uca-root-g2";assert.throws(()=>project(sheca,p,endpoints,multiCA));
});

test("multi-CA filters combine without inferring certificate roles",()=>{
 const d=project(sheca,satl,endpoints,multiCA);
 for(const [ca,count] of [["SHECA",17],["CFCA",4],["BJCA",6],["GDCA",5]])assert.equal(searchRows(d,"","","","",ca).length,count);
 assert.equal(searchRows(d,"","CHAIN_LISTING","DOCUMENT_SIGNING_RESEARCH","OFFICIAL_PAGE_OBSERVED","BJCA").length,2);
 assert.equal(searchRows(d,"","ROOT","","","GDCA").length,0);
 assert.equal(searchRows(d,"81869fe44b0c","","","","GDCA").length,1);
 assert.equal(searchRows(d,"81869fe44b0c","","","","CFCA").length,0);
 assert.equal(searchRows(d,"证书","","","","CFCA").length,3);
 const root=d.certificates.find(r=>r.id==="bjca-global-root-ca1");
 assert.equal(root.role,"CERTIFICATE_NAME_LEAD");assert.equal(root.validUntil,null);assert.equal(root.sha1,null);assert.equal(root.endpointLocated,false);
});
test("multi-CA projection rejects fabricated or unsafe evidence and strips private fields",()=>{
 const m=structuredClone(multiCA);m.entries[0].privateKey="secret";m.entries[0].downloadURL="https://private.invalid/file";
 const d=project(sheca,satl,endpoints,m);
 assert.equal(JSON.stringify(d).includes("secret"),false);assert.equal(JSON.stringify(d).includes("private.invalid"),false);
 const reject=fn=>{const v=structuredClone(multiCA);fn(v);assert.throws(()=>project(sheca,satl,endpoints,v))};
 reject(v=>{v.entries[0].sourceURL="javascript:alert(1)"});
 reject(v=>{v.entries[0].redistributionStatus="APPROVED"});
 reject(v=>{v.entries[0].track="constructor"});
 reject(v=>{v.entries[0].authority="__proto__"});
 reject(v=>{v.entries[0].publishedSHA256=v.entries[2].publishedSHA256});
 reject(v=>{v.entries[2].publishedSHA256.fingerprint="a".repeat(63)});
 reject(v=>{v.entries[2].publishedSHA256.sourceURL="https://example.com"});
 reject(v=>{v.entries[0].id="uca-root-g2"});
 reject(v=>{v.entries.reverse()});
 assert.throws(()=>project(sheca,satl,endpoints,undefined));
});
