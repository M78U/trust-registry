import {DATA} from "./data.js";
import {searchRows} from "./projection.js";
import {mountEvidenceGraph} from "./graph.js";
let graphUI;
const $=id=>document.getElementById(id);
const el=(tag,value,cls)=>{const e=document.createElement(tag);if(value!==undefined)e.textContent=String(value);if(cls)e.className=cls;return e};
const link=(label,url)=>{const a=el("a",label+" ↗");a.href=url;a.rel="noreferrer";return a};
const labels={ROOT:"根证书",INTERMEDIATE:"中间证书",LISTED:"目录列出",DISUSE:"停用目录",GENERAL_RESEARCH:"通用研究",SM2_RESEARCH:"国密研究",EVENT_RESEARCH:"事件证书",TIMESTAMP_RESEARCH:"时间戳",HISTORICAL_RESEARCH:"历史研究",TLS_ONLY_TRANSITION:"TLS 用途变更线索",SM_ROOT_STORE:"国密根证书清单"};
const policyNames={"document-signing":"电子文档签名","electronic-seal-signing":"电子签章","seal-maker":"制章","timestamping":"时间戳"};
function field(dl,name,value){dl.append(el("dt",name));const dd=el("dd");dd.append(value instanceof Node?value:document.createTextNode(value));dl.append(dd);}
function row(r){
 const d=el("details");d.id="ca-"+r.id;
 const s=el("summary"),n=el("div",r.label,"row-name");n.append(el("small",r.authority+" · "+labels[r.listingStatus]+" · "+labels[r.track]));s.append(n,el("span",labels[r.role],"row-role"));d.append(s);
 const section=el("div",undefined,"detail"),dl=el("dl");
 field(dl,"CA",r.authorityName);field(dl,"目录观察日期",r.observedOn);field(dl,"目录所列到期日",r.validUntil+"（未从 DER 核实）");
 field(dl,"官方 SHA-1",el("code",r.sha1));field(dl,"独立 SHA-256 线索",r.sha256Lead?el("code",r.sha256Lead.fingerprint):"尚未取得");
 if(r.sha256Lead)field(dl,"第三方证据",link(labels[r.sha256Lead.scope],r.sha256Lead.sourceURL));
 field(dl,"原始文件入口",r.endpointLocated?link("已定位 · 查看来源页面",r.endpointSourceURL):"待定位");
 field(dl,"来源",link("SHECA 公开目录",r.sourceURL));field(dl,"证书身份","尚未核对证书原件");field(dl,"分发许可","尚未审核");field(dl,"信任状态","NOT_ESTABLISHED");
 section.append(dl);const btn=el("button","在星图中探索","graph-action");btn.type="button";btn.addEventListener("click",()=>graphUI?.focusCatalog(r.id));section.append(btn);d.append(section);return d;
}
function render(){
 const rows=searchRows(DATA,$("search").value,$("role").value,$("track").value,$("status").value);
 $("result-count").textContent=rows.length+" / "+DATA.certificates.length+" 条研究目录记录";
 $("results").replaceChildren(...rows.map(row));
 if(!rows.length)$("results").append(el("p","没有匹配的目录记录。未找到并不表示证书不可信。","note"));
}
function openCA(id){
 $("search").value="";$("role").value="";$("track").value="";$("status").value="";render();
 const target=$("ca-"+id);if(target){target.open=true;target.querySelector("summary").focus();target.scrollIntoView({block:"center"});}
}
try{
 if(DATA.schemaVersion!=="1"||DATA.kind!=="PUBLIC_RESEARCH_CATALOG_PREVIEW"||DATA.trustStatus!=="NOT_ESTABLISHED"||DATA.releaseAuthenticated!==false)throw new Error("unexpected data profile");
 $("count-ca").textContent=DATA.certificates.length;$("count-hash").textContent=DATA.certificates.filter(r=>r.sha256Lead).length;$("count-satl").textContent=DATA.program.length;
 for(const id of ["search","role","track","status"])$(id).addEventListener(id==="search"?"input":"change",render);
 render();
 graphUI=mountEvidenceGraph(DATA,openCA);
 for(const r of DATA.program){
  const item=el("div",undefined,"program-row"),name=el("div",r.label);name.append(el("span"," · "+r.authority));const evidence=el("div");evidence.append(el("span","NAME_LEAD_ONLY · "+r.observedOn));
  if(r.candidateListingId){const a=el("a","查看同名 SHECA 目录线索");a.href="#ca-"+r.candidateListingId;a.addEventListener("click",e=>{e.preventDefault();openCA(r.candidateListingId)});evidence.append(a)}
  item.append(name,evidence);$("program-list").append(item);
 }
 for(const p of DATA.policies){const item=el("article",undefined,"policy");item.append(el("h3",policyNames[p.purpose]),el("code",p.id+" · v"+p.version),el("p","CN · 空策略模板 · 0 个授权信任锚"));$("policy-list").append(item)}
}catch{ $("result-count").textContent="研究目录无法载入，请重新打开页面。";$("result-count").className="error"; }
