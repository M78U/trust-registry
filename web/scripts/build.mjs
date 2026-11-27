import {readFile,mkdir,writeFile,copyFile,rm,readdir,stat} from "node:fs/promises";
import {fileURLToPath} from "node:url";
import {resolve,dirname} from "node:path";
import {project} from "./projection.mjs";
const here=dirname(fileURLToPath(import.meta.url)),web=resolve(here,".."),root=resolve(web,".."),dist=resolve(web,"dist");
const load=async name=>JSON.parse(await readFile(resolve(root,"pkg/sources",name),"utf8"));
const data=project(await load("sheca.json"),await load("satl.json"),await load("sheca-endpoints.json"),await load("multi-ca.json"));
await rm(dist,{recursive:true,force:true});await mkdir(dist);
const names=["index.html","style.css","app.js","graph.js","_headers","robots.txt","icon.svg","404.html"];
for(const name of names)await copyFile(resolve(web,"src",name),resolve(dist,name));
await copyFile(resolve(here,"projection.mjs"),resolve(dist,"projection.js"));
await copyFile(resolve(here,"graph-model.mjs"),resolve(dist,"graph-model.js"));
const dataModule="export const DATA = "+JSON.stringify(data)+";\n";
if(Buffer.byteLength(dataModule,"utf8")>256*1024)throw new Error("research data module budget exceeded");
await writeFile(resolve(dist,"data.js"),dataModule);
const output=await readdir(dist);
if(output.length!==names.length+3)throw new Error("unexpected static output");
for(const name of output){const s=await stat(resolve(dist,name));if(!s.isFile()||s.size>25*1024*1024)throw new Error("static asset size/type limit");}
console.log("Explorer preview built: "+data.certificates.length+" multi-CA research rows, "+data.program.length+" SATL name leads; no certificates or trusted anchors published.");
