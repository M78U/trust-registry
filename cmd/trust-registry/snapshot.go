package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/M78U/trust-registry/pkg/snapshot"
	"github.com/M78U/trust-registry/pkg/validation"
)

func runSnapshot(args []string,out io.Writer)error{
	if len(args)==0{return errors.New("usage: snapshot build | verify | sign-research | authenticate-research | install-research | load-research | find-installed | verify-installed-path | export-candidates | diff")}
	if args[0]=="diff"{return runSnapshotDiff(args,out)}
	if args[0]=="install-research"||args[0]=="load-research"||args[0]=="find-installed"||args[0]=="verify-installed-path"{return runInstalledSnapshot(args,out)}
	if args[0]=="sign-research"||args[0]=="authenticate-research"{return runResearchSignature(args,out)}
	flags:=flag.NewFlagSet("snapshot "+args[0],flag.ContinueOnError)
	enc:=json.NewEncoder(out)
	switch args[0]{
	case "build":
		root:=flags.String("registry","registry","local CA inventory")
		path:=flags.String("out","","new local research envelope file")
		sequence:=flags.Uint64("sequence",0,"explicit positive snapshot sequence")
		revision:=flags.String("revision","","source Git commit (asserted)")
		created:=flags.String("created-at","","explicit RFC3339 time")
		expires:=flags.String("expires-at","","explicit RFC3339 time")
		var paths []string
		flags.Func("policy","policy document (repeatable)",func(v string)error{if v==""||len(paths)>=validation.MaxPolicyDocuments{return errors.New("invalid policy path or limit")};paths=append(paths,v);return nil})
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=0||*path==""||*sequence==0||*revision==""||*created==""||*expires==""{return errors.New("out, sequence, revision, created-at, expires-at required")}
		c,err:=time.Parse(time.RFC3339Nano,*created);if err!=nil{return err}
		e,err:=time.Parse(time.RFC3339Nano,*expires);if err!=nil{return err}
		s,err:=registry.OpenStore(*root);if err!=nil{return err}
		docs:=make([]policy.Document,0,len(paths))
		for _,p:=range paths{d,err:=policy.LoadDocument(p);if err!=nil{return err};docs=append(docs,d)}
		raw,r,err:=snapshot.Build(s,docs,snapshot.Options{Sequence:*sequence,SourceRevision:*revision,CreatedAt:c.UTC(),ExpiresAt:e.UTC()});if err!=nil{return err}
		f,err:=os.OpenFile(*path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
		if _,err=f.Write(raw);err==nil{err=f.Sync()};closeErr:=f.Close();if err==nil{err=closeErr}
		if err!=nil{_ = os.Remove(*path);return err}
		return enc.Encode(r)
	case "export-candidates":
		pin:=flags.String("snapshot-sha256","","independently supplied exact snapshot digest")
		at:=flags.String("at","","explicit current time RFC3339")
		cert:=flags.String("certificate","","optional local signer certificate for matched-ancestor selection")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=1||*pin==""||*at==""{return errors.New("usage: snapshot export-candidates --snapshot-sha256 HEX --at RFC3339 [--certificate FILE] SNAPSHOT")}
		when,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
		raw,err:=readSnapshot(flags.Arg(0));if err!=nil{return err}
		v,_,err:=snapshot.LoadPinnedResearch(raw,*pin,when.UTC());if err!=nil{return err}
		var input []byte
		if *cert!=""{input,err=readInput(*cert);if err!=nil{return err};if len(input)==0{return errors.New("empty certificate")}}
		bundle,err:=v.CandidateBundle(input);if err!=nil{return err}
		_,err=out.Write(bundle);return err
	case "verify":
		pin:=flags.String("manifest-sha256","","optional caller-pinned manifest digest")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=1{return errors.New("usage: snapshot verify [--manifest-sha256 HEX] FILE")}
		raw,err:=readSnapshot(flags.Arg(0));if err!=nil{return err}
		r,err:=snapshot.Verify(raw,*pin);if err!=nil{return err}
		return enc.Encode(r)
	default:return errors.New("unknown snapshot command")
	}
}

func readSnapshot(path string)([]byte,error){
	info,err:=os.Lstat(path);if err!=nil{return nil,err}
	if !info.Mode().IsRegular()||info.Size()>snapshot.MaxEnvelopeBytes{return nil,errors.New("invalid snapshot file type or size")}
	f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
	opened,err:=f.Stat();if err!=nil{return nil,err}
	if !opened.Mode().IsRegular()||!os.SameFile(info,opened){return nil,errors.New("snapshot changed while opening")}
	b,err:=io.ReadAll(io.LimitReader(f,snapshot.MaxEnvelopeBytes+1));if err!=nil{return nil,err}
	if len(b)>snapshot.MaxEnvelopeBytes{return nil,errors.New("snapshot too large")}
	return b,nil
}
