// Only research evidence associations. This module deliberately has no
// issuer-edge constructor, trust elevation or certificate byte input.
export function evidenceGraph(data){
 if(data.kind!=="PUBLIC_RESEARCH_CATALOG_PREVIEW"||data.trustStatus!=="NOT_ESTABLISHED"||data.releaseAuthenticated!==false)throw new Error("research projection required");
 const nodes=new Map(),edges=[];
 const add=(id,kind,label,detail,extra={})=>{
  if(!nodes.has(id))nodes.set(id,{id,kind,label,detail,...extra});
  return id;
 };
 const edge=(a,b,kind)=>{if(!nodes.has(a)||!nodes.has(b)||a===b)throw new Error("invalid research relation");edges.push({a,b,kind})};
 const catalog=add("source:sheca","SOURCE","SHECA 公开目录","目录记录来源",{url:"https://www.sheca.com/repository"});
 const program=add("source:satl","SOURCE","SATL 公开列表","搜索索引中的名称线索",{url:"https://satl.ofd.cn/list"});
 const auxiliary=add("source:imtrust","SOURCE","SHECA 辅助资料","原始文件入口的来源页面",{url:"https://www.imtrust.cn/jishuwendang/dmqmwd/96.html"});
 for(const row of data.certificates){
  const id=add("ca:"+row.id,"CATALOG",row.label,"证书目录条目 · 尚未核对 DER",{catalogId:row.id});
  edge(id,catalog,"CATALOG_LISTING");
  if(row.endpointLocated)edge(id,auxiliary,"DOWNLOAD_ENTRY_LEAD");
  if(row.sha256Lead){
   const lead=row.sha256Lead;
   const fp=add("hash:"+row.id,"FINGERPRINT","SHA-256 线索",lead.fingerprint,{scope:lead.scope});
   const source=add("source:"+lead.sourceURL,"SOURCE",lead.scope==="TLS_ONLY_TRANSITION"?"Mozilla Bugzilla":"Huawei 国密根清单","第三方指纹声明来源",{url:lead.sourceURL});
   edge(id,fp,"FINGERPRINT_CLAIM");edge(fp,source,"CLAIM_SOURCE");
  }
 }
 for(const row of data.program){
  const id=add("satl:"+row.id,"PROGRAM",row.label,"SATL 名称线索 · 未确认成员资格",{authority:row.authority});
  edge(id,program,"INDEXED_NAME_LEAD");
  if(row.candidateListingId)edge(id,"ca:"+row.candidateListingId,"NAME_ONLY_ASSOCIATION");
 }
 if(nodes.size>4096||edges.length>8192)throw new Error("research graph size limit");
 return {kind:"RESEARCH_EVIDENCE_GRAPH",trustStatus:"NOT_ESTABLISHED",verifiedIssuerEdges:0,nodes:[...nodes.values()],edges};
}
// Direct neighbors only. No transitive inference, including through a common
// listing source. Filtering never creates an inferred edge.
export function neighborhood(graph,focus,filter=""){
 const center=graph.nodes.find(n=>n.id===focus);
 if(!center)throw new Error("unknown graph focus");
 const byID=new Map(graph.nodes.map(n=>[n.id,n]));
 const neighbors=[];
 for(const e of graph.edges){
  if(e.a!==focus&&e.b!==focus||filter&&filter!==e.kind)continue;
  const n=byID.get(e.a===focus?e.b:e.a);
  if(!n)throw new Error("missing graph endpoint");
  neighbors.push({node:n,kind:e.kind});
 }
 neighbors.sort((a,b)=>a.kind.localeCompare(b.kind,"en")||a.node.id.localeCompare(b.node.id,"en"));
 return {center,neighbors};
}
export const EDGE_LABELS={CATALOG_LISTING:"目录收录",DOWNLOAD_ENTRY_LEAD:"文件入口线索",FINGERPRINT_CLAIM:"指纹声明",CLAIM_SOURCE:"声明来源",INDEXED_NAME_LEAD:"索引名称线索",NAME_ONLY_ASSOCIATION:"同名关联"};
export const NODE_LABELS={CATALOG:"证书目录条目",PROGRAM:"信任列表名称",SOURCE:"来源页面",FINGERPRINT:"指纹线索"};
