import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,symlinkSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {collectPackages,parsePackages,parseOptions,checkSource} from './cli-license-evidence.mjs';

test('collect selected package ancestor notices and Go runtime, omit unrelated source',()=>{
  const temp=mkdtempSync(join(tmpdir(),'cli-licenses-'));
  try{
    const project=join(temp,'project'),go=join(temp,'go'),mod=join(temp,'mod'),out=join(temp,'out');
    for(const d of [project,join(go,'src','fmt'),join(mod,'a','b'),join(mod,'unused')])mkdirSync(d,{recursive:true});
    for(const [d,n,s] of [[go,'LICENSE','Go terms'],[mod,'LICENSE','module terms'],[join(mod,'a'),'PATENTS','patents'],[join(mod,'a','b'),'NOTICE','notice'],[join(mod,'unused'),'LICENSE','unused']])writeFileSync(join(d,n),s);
    symlinkSync(join(mod,'LICENSE'),join(mod,'a','COPYING'));
    const p={ImportPath:'example.org/mod/a/b',Dir:join(mod,'a','b'),Module:{Path:'example.org/mod',Version:'v1.0.0',Dir:mod}};
    const r=collectPackages([p,p,{ImportPath:'fmt',Standard:true,Dir:join(go,'src','fmt')}],go,project,out,{GOVERSION:'go1.26.0'});
    const m=r.modules.find(x=>x.id.startsWith('example.org'));
    assert.deepEqual(m.files.map(x=>x.path).sort(),['LICENSE','a/PATENTS','a/b/NOTICE']);
    assert.equal(m.packages.length,1);assert.equal(m.warnings.length,1);
    assert.equal(readFileSync(join(out,m.files[0].evidenceFile),'utf8'),'module terms');
    assert.equal(r.modules.find(x=>x.id.startsWith('go-toolchain')).files[0].path,'LICENSE');
    assert.equal(r.distributionAuthorized,false);assert.ok(!JSON.stringify(r).includes(temp));
    assert.throws(()=>collectPackages([{...p,Dir:project}],go,project,join(temp,'other'),{GOVERSION:'go1.26.0'}),/outside/);
    assert.throws(()=>collectPackages([{...p,Module:{...p.Module,Replace:{}}}],go,project,join(temp,'other'),{GOVERSION:'go1.26.0'}),/replacement/);
  }finally{rmSync(temp,{recursive:true,force:true});}
});
test('reject incomplete or empty package graph',()=>{
  assert.equal(parsePackages('{"ImportPath":"fmt","Dir":"/go/src/fmt"}\n{"ImportPath":"unsafe"}').length,2);
  assert.throws(()=>parsePackages(''));assert.throws(()=>parsePackages('{"ImportPath":"x","Incomplete":true}'));
});

test('explicit release checkout requires exact pin and external output',()=>{
  const temp=mkdtempSync(join(tmpdir(),'cli-release-'));
  try{
    const tool=join(temp,'tool'),release=join(temp,'release'),out=join(temp,'out');
    mkdirSync(tool);mkdirSync(release);
    const run=(cmd,args)=>execFileSync(cmd,args,{cwd:release,encoding:'utf8',stdio:['ignore','pipe','pipe']});
    run('git',['init','-q']);run('git',['config','user.email','test@example.invalid']);run('git',['config','user.name','Fixture']);
    writeFileSync(join(release,'go.mod'),'module example.invalid/release\n');writeFileSync(join(release,'go.sum'),'');
    run('git',['add','go.mod','go.sum']);run('git',['commit','-qm','fixture']);
    const pin=run('git',['rev-parse','HEAD']).trim();
    const args=['--out='+out,'--source='+release,'--expected-revision='+pin];
    const options=parseOptions(args,tool);
    assert.equal(options.expected,pin);assert.equal(checkSource(options.root,pin,run),pin);
    assert.throws(()=>parseOptions(args.slice(0,2),tool),/usage/);
    assert.throws(()=>parseOptions([...args,'--out='+out],tool),/usage/);
    assert.throws(()=>parseOptions([args[0],args[1],'--expected-revision=main'],tool),/commit SHA/);
    assert.throws(()=>parseOptions(['--out='+join(release,'out'),...args.slice(1)],tool),/outside/);
    assert.throws(()=>parseOptions(['--out='+join(tool,'out'),...args.slice(1)],tool),/outside/);
    assert.throws(()=>checkSource(options.root,'0'.repeat(40),run),/revision mismatch/);
    writeFileSync(join(release,'untracked'),'fixture');
    assert.throws(()=>checkSource(options.root,pin,run),/clean checkout/);
  }finally{rmSync(temp,{recursive:true,force:true});}
});
