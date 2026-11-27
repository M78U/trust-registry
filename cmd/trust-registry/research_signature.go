package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/M78U/trust-registry/pkg/snapshot"
)

func readSmall(path string,limit int64)([]byte,error){
	info,err:=os.Lstat(path);if err!=nil{return nil,err}
	if !info.Mode().IsRegular()||info.Size()>limit{return nil,errors.New("invalid input file type or size")}
	f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
	opened,err:=f.Stat();if err!=nil{return nil,err}
	if !opened.Mode().IsRegular()||!os.SameFile(info,opened){return nil,errors.New("input changed while opening")}
	b,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err}
	if int64(len(b))>limit{return nil,errors.New("input exceeds size limit")}
	return b,nil
}
func readPEM(path,kind string)([]byte,error){
	raw,err:=readSmall(path,16<<10);if err!=nil{return nil,err}
	block,rest:=pem.Decode(raw)
	if block==nil||block.Type!=kind||len(block.Headers)!=0||len(bytes.TrimSpace(rest))!=0||!bytes.HasPrefix(bytes.TrimSpace(raw),[]byte("-----BEGIN "+kind+"-----")){return nil,errors.New("expected exactly one PEM key")}
	return block.Bytes,nil
}
func writeNew(path string,raw []byte)error{
	f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
	if _,err=f.Write(raw);err==nil{err=f.Sync()};closeErr:=f.Close();if err==nil{err=closeErr}
	if err!=nil{_ = os.Remove(path)}
	return err
}

func runResearchSignature(args []string,out io.Writer)error{
	flags:=flag.NewFlagSet("snapshot "+args[0],flag.ContinueOnError)
	switch args[0]{
	case "sign-research":
		path:=flags.String("key","","local offline PKCS#8 Ed25519 private key PEM")
		dest:=flags.String("out","","new detached signature JSON file")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=1||*path==""||*dest==""{return errors.New("usage: snapshot sign-research --key FILE --out FILE SNAPSHOT")}
		raw,err:=readSnapshot(flags.Arg(0));if err!=nil{return err}
		keyDER,err:=readPEM(*path,"PRIVATE KEY");if err!=nil{return err}
		defer clear(keyDER)
		k,err:=x509.ParsePKCS8PrivateKey(keyDER);if err!=nil{return errors.New("invalid PKCS#8 key")}
		key,ok:=k.(ed25519.PrivateKey);if !ok{return errors.New("Ed25519 private key required")}
		defer clear(key)
		sig,err:=snapshot.SignResearch(raw,key);if err!=nil{return err}
		data,err:=snapshot.SignatureBytes(sig);if err!=nil{return err}
		if err:=writeNew(*dest,data);err!=nil{return err}
		return json.NewEncoder(out).Encode(map[string]string{"keyId":sig.KeyID,"snapshotSHA256":sig.SnapshotSHA256,"status":"RESEARCH_SIGNATURE_CREATED"})
	case "authenticate-research":
		var keyPaths,sigPaths []string
		add:=func(dst *[]string)func(string)error{return func(v string)error{if v==""||len(*dst)>=snapshot.MaxResearchKeys{return errors.New("invalid path or count limit")};*dst=append(*dst,v);return nil}}
		flags.Func("public-key","independently pinned SPKI Ed25519 public key PEM (repeatable)",add(&keyPaths))
		flags.Func("signature","detached signature JSON (repeatable)",add(&sigPaths))
		threshold:=flags.Int("threshold",0,"required distinct signatures")
		at:=flags.String("at","","explicit current UTC time RFC3339")
		bootstrap:=flags.Bool("bootstrap",false,"explicitly accept absence of caller checkpoint")
		seq:=flags.Uint64("previous-sequence",0,"previous accepted sequence")
		hash:=flags.String("previous-sha256","","previous accepted snapshot hash")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=1||*at==""||*threshold<1||len(keyPaths)==0||len(sigPaths)==0{return errors.New("snapshot, at, threshold, public-key and signature required")}
		var previous *snapshot.Checkpoint
		if *bootstrap{if *seq!=0||*hash!=""{return errors.New("bootstrap conflicts with previous checkpoint")}}else{if *seq==0||*hash==""{return errors.New("previous checkpoint or explicit bootstrap required")};previous=&snapshot.Checkpoint{Sequence:*seq,SnapshotSHA256:*hash}}
		when,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
		keys:=[]ed25519.PublicKey{}
		for _,p:=range keyPaths{der,err:=readPEM(p,"PUBLIC KEY");if err!=nil{return err};k,err:=x509.ParsePKIXPublicKey(der);if err!=nil{return err};key,ok:=k.(ed25519.PublicKey);if !ok{return errors.New("Ed25519 public key required")};keys=append(keys,key)}
		sigs:=[]snapshot.Signature{}
		for _,p:=range sigPaths{raw,err:=readSmall(p,snapshot.MaxSignatureBytes);if err!=nil{return err};s,err:=snapshot.DecodeSignature(raw);if err!=nil{return err};sigs=append(sigs,s)}
		raw,err:=readSnapshot(flags.Arg(0));if err!=nil{return err}
		report,err:=snapshot.AuthenticateResearch(raw,sigs,keys,*threshold,when.UTC(),previous);if err!=nil{return err}
		return json.NewEncoder(out).Encode(report)
	default:return errors.New("unknown research signature command")
	}
}
