import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {project} from "./projection.mjs";
import {evidenceGraph,neighborhood,EDGE_LABELS} from "./graph-model.mjs";
const load=async n=>JSON.parse(await readFile(new URL("../../pkg/sources/"+n,import.meta.url),"utf8"));
const data=project(await load("sheca.json"),await load("satl.json"),await load("sheca-endpoints.json"));
test("evidence graph contains no verified issuer or trust edges",()=>{
 const g=evidenceGraph(data);
 assert.equal(g.nodes.length,32);
 assert.equal(g.edges.length,42);
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
