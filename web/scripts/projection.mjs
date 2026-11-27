// A deliberately restricted public research projection. Never accepts a
// local inventory, signed snapshot, signer certificate or arbitrary paths.
const hash=(x,n)=>typeof x==="string"&&x.length===n&&/^[0-9a-f]+$/.test(x);
const text=(x)=>typeof x==="string"&&x.length>0&&x.length<=512;
const id=x=>text(x)&&/^[a-z0-9][a-z0-9-]*$/.test(x);
const date=x=>typeof x==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString().slice(0,10)===x;
const assert=(v,m)=>{if(!v)throw new Error(m)};
const list=(x)=>Array.isArray(x)&&x.length<=1000;
const knownEvidenceURL=x=>x==="https://bugzilla.mozilla.org/show_bug.cgi?id=2088275"||x==="https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-sm-root-certificate-20261030";
const authorities={
 CFCA:{name:"中金金融认证中心",sources:["https://www.cfca.com.cn/zhengshuzizhu/"]},
 BJCA:{name:"北京数字认证",sources:["https://www.bjca.cn/service/down_198.html","https://repo.bjca.cn/global/cert/"]},
 GDCA:{name:"数安时代",sources:["https://www.gdca.com.cn/customer_service/knowledge_universe/ca_cq/"]}
};
const multiTracks={GENERAL:"GENERAL_RESEARCH",SM2:"SM2_RESEARCH",DOCUMENT_SIGNING:"DOCUMENT_SIGNING_RESEARCH",TIMESTAMPING:"TIMESTAMP_RESEARCH"};
const multiEvidence={
 MICROSOFT_DOCUMENT_SIGNING_LIST:{authorities:["CFCA"],url:"https://ccadb.my.salesforce-sites.com/microsoft/includedcacertificatereportformsft"},
 MOZILLA_ROOT_INCLUSION_RECORD:{authorities:["BJCA"],url:"https://bugzilla.mozilla.org/show_bug.cgi?id=1822921"},
 HUAWEI_SM_ROOT_LIST:{authorities:["BJCA","GDCA"],url:"https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-sm-root-certificate-20261030"},
 HUAWEI_ROOT_LIST:{authorities:["GDCA"],url:"https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-root-certificate-20261030"}
};
function multiRows(c,byID){
 assert(c?.schemaVersion==="1"&&c.coverage==="SELECTED_RESEARCH_LEADS"&&c.trustStatus==="NOT_ESTABLISHED"&&date(c.observedOn)&&Array.isArray(c.entries)&&c.entries.length>0&&c.entries.length<=256,"invalid multi-CA source");
 let previous="";
 const fingerprints=new Set([...byID.values()].map(r=>r.sha256Lead?.fingerprint).filter(Boolean));
 for(const e of c.entries){
  const a=Object.hasOwn(authorities,e.authority)?authorities[e.authority]:null;
  assert(id(e.id)&&e.id>previous&&!byID.has(e.id)&&text(e.label)&&e.label.length<=256&&a&&a.sources.includes(e.sourceURL)&&e.redistributionStatus==="NOT_REVIEWED"&&["CHAIN_LISTING","CERTIFICATE_NAME_LEAD"].includes(e.kind)&&Object.hasOwn(multiTracks,e.track)&&["OFFICIAL_PAGE_OBSERVED","OFFICIAL_SEARCH_INDEX_ONLY","OFFICIAL_RELATED_POLICY_PAGE"].includes(e.sourceStatus),"invalid multi-CA row");
  previous=e.id;
  let lead=null;
  if(e.publishedSHA256!==undefined){
   const h=e.publishedSHA256;
   assert(h&&Object.hasOwn(multiEvidence,h.scope),"invalid multi-CA evidence scope");
   const s=multiEvidence[h.scope];
   assert(e.kind==="CERTIFICATE_NAME_LEAD"&&hash(h.fingerprint,64)&&!fingerprints.has(h.fingerprint)&&s.authorities.includes(e.authority)&&h.sourceURL===s.url,"invalid multi-CA fingerprint lead");
   fingerprints.add(h.fingerprint);
   lead={fingerprint:h.fingerprint,sourceURL:h.sourceURL,scope:h.scope};
  }
  // Never infer certificate role, expiry, direct download URL or identity.
  byID.set(e.id,{id:e.id,label:e.label,authority:e.authority,authorityName:a.name,role:e.kind,listingStatus:e.sourceStatus,sha1:null,validUntil:null,track:multiTracks[e.track],observedOn:c.observedOn,sourceURL:e.sourceURL,endpointLocated:false,sha256Lead:lead});
 }
}

export function project(sheca,satl,endpoints,multiCA){
 assert(sheca.schemaVersion==="1"&&sheca.authorityId==="cn.sheca"&&sheca.repositoryURL==="https://www.sheca.com/repository"&&sheca.coverage==="SELECTED_RESEARCH_ROWS"&&date(sheca.observedOn)&&text(sheca.authorityName)&&list(sheca.entries),"invalid SHECA source");
 assert(satl.schemaVersion==="1"&&satl.programId==="satl"&&satl.listingURL==="https://satl.ofd.cn/list"&&satl.strategyURL==="https://satl.ofd.cn/strategy"&&satl.evidenceStatus==="SEARCH_INDEXED_PAGE_ONLY"&&satl.coverage==="SELECTED_INDEXED_PAGE_ROWS"&&satl.trustStatus==="NOT_ESTABLISHED"&&date(satl.observedOn)&&list(satl.entries),"invalid SATL source");
 assert(list(endpoints),"invalid acquisition leads");
 const byID=new Map();
 for(const e of sheca.entries){
  assert(id(e.id)&&!byID.has(e.id)&&text(e.label)&&["ROOT","INTERMEDIATE"].includes(e.publishedRole)&&["LISTED","DISUSE"].includes(e.publishedStatus)&&hash(e.publishedSHA1,40)&&date(e.publishedValidUntil)&&["GENERAL_RESEARCH","SM2_RESEARCH","EVENT_RESEARCH","TIMESTAMP_RESEARCH","HISTORICAL_RESEARCH"].includes(e.researchTrack)&&e.redistributionStatus==="NOT_REVIEWED","invalid SHECA row");
  byID.set(e.id,{id:e.id,label:e.label,authority:"SHECA",authorityName:sheca.authorityName,role:e.publishedRole,listingStatus:e.publishedStatus,sha1:e.publishedSHA1,validUntil:e.publishedValidUntil,track:e.researchTrack,observedOn:sheca.observedOn,sourceURL:sheca.repositoryURL,endpointLocated:false,sha256Lead:null});
 }
 const endpointIDs=new Set();
 for(const e of endpoints){
  assert(byID.has(e.listingId)&&!endpointIDs.has(e.listingId)&&e.listingURL==="https://www.imtrust.cn/jishuwendang/dmqmwd/96.html"&&date(e.observedOn),"invalid endpoint reference");
  endpointIDs.add(e.listingId);
  const row=byID.get(e.listingId);row.endpointLocated=true;row.endpointSourceURL=e.listingURL;
  if(e.publishedSHA256){
   const h=e.publishedSHA256;
   assert(hash(h.fingerprint,64)&&knownEvidenceURL(h.sourceURL)&&["TLS_ONLY_TRANSITION","SM_ROOT_STORE"].includes(h.scope),"invalid independent fingerprint lead");
   row.sha256Lead={fingerprint:h.fingerprint,sourceURL:h.sourceURL,scope:h.scope};
  }
 }
 // Original SATL references resolve against SHECA only.
 const seen=new Set();
 const program=satl.entries.map(e=>{
  assert(id(e.id)&&!seen.has(e.id)&&text(e.label)&&text(e.authority)&&e.matchStatus==="NAME_LEAD_ONLY","invalid SATL row");seen.add(e.id);
  const match=e.candidateListingId||null;
  assert(match===null||(byID.has(match)&&byID.get(match).label===e.label),"invalid name reference");
  return {id:e.id,label:e.label,authority:e.authority,observedOn:satl.observedOn,sourceURL:satl.listingURL,candidateListingId:match};
 });
 multiRows(multiCA,byID);
 return {schemaVersion:"1",kind:"PUBLIC_RESEARCH_CATALOG_PREVIEW",trustStatus:"NOT_ESTABLISHED",releaseAuthenticated:false,certificates:[...byID.values()],program,policies:["document-signing","electronic-seal-signing","seal-maker","timestamping"].map(p=>({id:"cn."+p,purpose:p,jurisdiction:"CN",version:1,anchors:0,status:"EMPTY_TEMPLATE"}))};
}
export function searchRows(data,query,role,track,status,authority=""){
 const q=query.trim().toLowerCase();
 return data.certificates.filter(r=>(!authority||r.authority===authority)&&(!role||r.role===role)&&(!track||r.track===track)&&(!status||r.listingStatus===status)&&(!q||[r.id,r.label,r.authority,r.authorityName,r.sha1||"",r.sha256Lead?.fingerprint||""].some(v=>v.toLowerCase().includes(q))));
}
