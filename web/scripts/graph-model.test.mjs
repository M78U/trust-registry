import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {project} from "./projection.mjs";
import {evidenceGraph,neighborhood,EDGE_LABELS} from "./graph-model.mjs";
const load=async n=>JSON.parse(await readFile(new URL("../../pkg/sources/"+n,import.meta.url),"utf8"));
const data=project(await load("sheca.json"),await load("satl.json"),await load("sheca-endpoints.json"),await load("multi-ca.json"));
test("evidence graph contains no verified issuer or trust edges",()=>{
 const g=evidenceGraph(data);
 assert.equal(g.nodes.length,59);
 assert.equal(g.edges.length,67);
 assert.equal(g.verifiedIssuerEdges,0);
 assert.equal(g.trustStatus,"NOT_ESTABLISHED");
 assert.equal(new Set(g.nodes.map(n=>n.id)).size,g.nodes.length);
 for(const e of g.edges){assert.ok(EDGE_LABELS[e.kind]);assert.ok(g.nodes.some(n=>n.id===e.a));assert.ok(g.nodes.some(n=>n.id===e.b))}
 assert.deepEqual(evidenceGraph(data),g);
});
test("direct relations, filters and no inference via shared source",()=>{
 const g=evidenceGraph(data);
 const n=neighborhood(g,"ca:uca-root-g2");
 assert.equal(n.neighbors.length,3);
 assert.equal(neighborhood(g,"ca:uca-root-g2","NAME_ONLY_ASSOCIATION").neighbors[0].node.id,"satl:sheca-g2");
 assert.equal(neighborhood(g,"ca:uca-sm2","FINGERPRINT_CLAIM").neighbors[0].node.id,"hash:uca-sm2");
 assert.equal(neighborhood(g,"ca:uca-sm2","NAME_ONLY_ASSOCIATION").neighbors.length,0);
 assert.equal(n.neighbors.some(x=>x.node.id==="ca:uca-sm2"),false);
 assert.equal(neighborhood(g,"source:sheca").neighbors.length,17);
 assert.throws(()=>neighborhood(g,"not-a-node"));
 assert.throws(()=>evidenceGraph({...data,releaseAuthenticated:true}));
});

test("multi-CA graph preserves source and fingerprint scope without inference",()=>{
 const g=evidenceGraph(data);
 const chain=neighborhood(g,"ca:cfca-document-chain");
 assert.equal(chain.neighbors.length,1);assert.equal(chain.neighbors[0].kind,"CHAIN_LISTING");
 const ca=neighborhood(g,"ca:cfca-identity-ca");
 assert.equal(ca.neighbors.length,2);
 assert.equal(neighborhood(g,"ca:cfca-identity-ca","CERTIFICATE_NAME_LEAD").neighbors.length,1);
 assert.equal(neighborhood(g,"ca:cfca-identity-ca","FINGERPRINT_CLAIM").neighbors[0].node.scope,"MICROSOFT_DOCUMENT_SIGNING_LIST");
 assert.equal(neighborhood(g,"ca:gdca-trustauth-e1-ca","FINGERPRINT_CLAIM").neighbors.length,0);
 assert.equal(neighborhood(g,"ca:gdca-gm-sm2-root","NAME_ONLY_ASSOCIATION").neighbors.length,0);
 assert.equal(ca.neighbors.some(x=>x.node.id==="ca:cfca-document-chain"),false);
});
