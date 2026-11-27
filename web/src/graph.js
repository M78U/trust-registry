import {evidenceGraph,neighborhood,EDGE_LABELS,NODE_LABELS} from "./graph-model.js";
const NS="http://www.w3.org/2000/svg";
const $=id=>document.getElementById(id);
const el=(tag,value,cls)=>{const e=document.createElement(tag);if(value!==undefined)e.textContent=value;if(cls)e.className=cls;return e};
const svgEl=(tag,attrs={})=>{const e=document.createElementNS(NS,tag);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,String(v));return e};
const shape=(node,x,y,r)=>{
 const group=svgEl("g",{transform:"translate("+x+" "+y+")",class:"graph-node graph-"+node.kind.toLowerCase()});
 if(node.kind==="SOURCE"){
  group.append(svgEl("path",{d:`M0 ${-r} Q${r*.18} ${-r*.18} ${r} 0 Q${r*.18} ${r*.18} 0 ${r} Q${-r*.18} ${r*.18} ${-r} 0 Q${-r*.18} ${-r*.18} 0 ${-r}Z`}));
 }else if(node.kind==="CATALOG"){
  group.append(svgEl("circle",{r:r*.72}));group.append(svgEl("ellipse",{rx:r*1.23,ry:r*.39,transform:"rotate(-27)",class:"graph-ring"}));
 }else if(node.kind==="PROGRAM"){
  group.append(svgEl("circle",{r:r*.66}));group.append(svgEl("circle",{r:r,class:"graph-outline"}));
 }else{group.append(svgEl("circle",{r:r*.48}));}
 return group;
};
export function mountEvidenceGraph(data,openCA){
 const graph=evidenceGraph(data),select=$("graph-focus"),filter=$("graph-filter"),panel=$("graph-detail"),list=$("graph-neighbors"),svg=$("evidence-svg"),count=$("graph-count");
 const byID=new Map(graph.nodes.map(n=>[n.id,n]));
 for(const [kind,label] of Object.entries(NODE_LABELS)){
  const g=el("optgroup");g.label=label;
  for(const n of graph.nodes.filter(n=>n.kind===kind)){const o=el("option",n.label+(kind==="FINGERPRINT"?" · "+n.detail.slice(0,12):""));o.value=n.id;g.append(o)}
  select.append(g);
 }
 for(const [kind,label] of Object.entries(EDGE_LABELS)){const o=el("option",label);o.value=kind;filter.append(o)}
 const choose=id=>{if(!byID.has(id))return;select.value=id;filter.value="";render()};
 function render(){
  const {center,neighbors}=neighborhood(graph,select.value,filter.value);
  svg.replaceChildren();
  const desc=svgEl("desc",{id:"graph-description"});desc.textContent=center.label+"，"+neighbors.length+" 条直接研究关系，没有经过验证的签发边。";svg.append(desc);
  const shown=neighbors.slice(0,12),cx=340,cy=215;
  const orbit=svgEl("ellipse",{cx,cy,rx:245,ry:153,class:"graph-orbit"});svg.append(orbit);
  const points=shown.map((n,i)=>{const angle=-Math.PI/2+i*2*Math.PI/shown.length;return {n,x:cx+245*Math.cos(angle),y:cy+153*Math.sin(angle)}});
  for(const {n,x,y} of points){svg.append(svgEl("line",{x1:cx,y1:cy,x2:x,y2:y,class:"graph-edge "+(n.kind==="NAME_ONLY_ASSOCIATION"?"graph-name-edge":"")}))}
  svg.append(shape(center,cx,cy,42));
  for(const {n,x,y} of points){
   const g=shape(n.node,x,y,17);g.setAttribute("role","button");g.setAttribute("tabindex","0");g.setAttribute("aria-label",EDGE_LABELS[n.kind]+"："+n.node.label);
   const title=svgEl("title");title.textContent=n.node.label;g.append(title);
   g.addEventListener("click",()=>{choose(n.node.id);select.focus()});
   g.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();choose(n.node.id);select.focus()}});
   svg.append(g);
   const label=svgEl("text",{x,y:y+30,"text-anchor":"middle",class:"graph-label"});const name=n.node.label;label.textContent=name.length>19?name.slice(0,17)+"…":name;svg.append(label);
  }
  const label=svgEl("text",{x:cx,y:cy+62,"text-anchor":"middle",class:"graph-center-label"});label.textContent=center.label.length>30?center.label.slice(0,28)+"…":center.label;svg.append(label);
  count.textContent=neighbors.length+" 条直接研究关系 · 已验证签发边 0"+(neighbors.length>12?" · 图中显示前 12 条，下方为完整列表":"");
  panel.replaceChildren(el("p",NODE_LABELS[center.kind],"eyebrow"),el("h3",center.label),el("p",center.detail,"note"));
  if(center.authority)panel.append(el("p",center.authority,"note"));
  if(center.scope)panel.append(el("p","声明范围："+center.scope,"note"));
  if(center.url){const a=el("a","查看来源 ↗");a.href=center.url;a.rel="noreferrer";panel.append(a)}
  if(center.catalogId){const button=el("button","查看目录详情","graph-action");button.type="button";button.addEventListener("click",()=>openCA(center.catalogId));panel.append(button)}
  list.replaceChildren();
  for(const n of neighbors){const button=el("button",undefined,"graph-neighbor");button.type="button";button.append(el("span",n.node.label),el("small",EDGE_LABELS[n.kind]+" · "+NODE_LABELS[n.node.kind]));button.addEventListener("click",()=>{choose(n.node.id);select.focus()});list.append(button)}
  if(!neighbors.length)list.append(el("p","此筛选条件下没有直接研究关系。","note"));
 }
 select.addEventListener("change",()=>{filter.value="";render()});filter.addEventListener("change",render);
 select.value=byID.has("ca:uca-root-g2")?"ca:uca-root-g2":graph.nodes[0].id;render();
 return {focusCatalog(id){choose("ca:"+id);$("relationships").scrollIntoView({block:"start"});select.focus()}};
}
