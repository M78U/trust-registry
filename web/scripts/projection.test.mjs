import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {project,searchRows} from "./projection.mjs";
const load=async name=>JSON.parse(await readFile(new URL("../../pkg/sources/"+name,import.meta.url),"utf8"));
const sheca=await load("sheca.json"),satl=await load("satl.json"),endpoints=await load("sheca-endpoints.json");
test("selected source leads, not certificate trust",()=>{
 const d=project(sheca,satl,endpoints);
 assert.equal(d.certificates.length,17);assert.equal(d.program.length,7);
 assert.equal(d.certificates.filter(r=>r.sha256Lead).length,3);
 assert.equal(d.certificates.filter(r=>r.endpointLocated).length,11);
 assert.equal(d.policies.reduce((n,p)=>n+p.anchors,0),0);
 assert.equal(d.releaseAuthenticated,false);
 assert.equal(searchRows(d,"UCA Root SM2","ROOT","SM2_RESEARCH","LISTED").length,1);
 assert.equal(searchRows(d,"d066fbe23ac1","","","").length,1);
 assert.equal(searchRows(d,"","INTERMEDIATE","","DISUSE").length,3);
});
test("projection ignores unknown/private payloads and rejects invalid evidence",()=>{
 const s=structuredClone(sheca);s.entries[0].der="secret";s.entries[0].privateKey="secret";
 const d=project(s,satl,endpoints);assert.equal(JSON.stringify(d).includes("secret"),false);
 const e=structuredClone(endpoints);e[1].publishedSHA256.sourceURL="javascript:alert(1)";
 assert.throws(()=>project(sheca,satl,e));
 const p=structuredClone(satl);p.entries[0].candidateListingId="uca-root-g2";assert.throws(()=>project(sheca,p,endpoints));
});
