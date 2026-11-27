package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/M78U/trust-registry/pkg/snapshot"
)

func runInstalledSnapshot(args []string,out io.Writer)error{
	flags:=flag.NewFlagSet("snapshot "+args[0],flag.ContinueOnError)
	dir:=flags.String("state","","private local installation directory")
	at:=flags.String("at","","explicit current UTC time RFC3339")
	threshold:=flags.Int("threshold",0,"pinned distinct signer threshold")
	var keyPaths,sigPaths []string
	add:=func(dst *[]string)func(string)error{return func(v string)error{if v==""||len(*dst)>=snapshot.MaxResearchKeys{return errors.New("invalid path or count limit")};*dst=append(*dst,v);return nil}}
	flags.Func("public-key","independently pinned Ed25519 public key PEM",add(&keyPaths))
	var bootstrap *bool
	var fp *string
	switch args[0]{
	case "install-research":
		flags.Func("signature","detached signature JSON",add(&sigPaths))
		bootstrap=flags.Bool("bootstrap",false,"explicit first installation")
	case "find-installed":
		fp=flags.String("fingerprint","","certificate DER SHA-256")
	case "load-research":
	default:return errors.New("unknown installed snapshot command")
	}
	if err:=flags.Parse(args[1:]);err!=nil{return err}
	if *dir==""||*at==""||*threshold<1||len(keyPaths)==0{return errors.New("state, at, threshold and public-key required")}
	when,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
	keys:=[]ed25519.PublicKey{}
	for _,p:=range keyPaths{der,err:=readPEM(p,"PUBLIC KEY");if err!=nil{return err};k,err:=x509.ParsePKIXPublicKey(der);if err!=nil{return err};key,ok:=k.(ed25519.PublicKey);if !ok{return errors.New("Ed25519 public key required")};keys=append(keys,key)}
	options:=snapshot.InstallationOptions{Keys:keys,Threshold:*threshold,At:when.UTC()}
	enc:=json.NewEncoder(out)
	if args[0]=="install-research"{
		if flags.NArg()!=1||len(sigPaths)==0{return errors.New("snapshot and signatures required")}
		options.Bootstrap=*bootstrap
		sigs:=[]snapshot.Signature{}
		for _,p:=range sigPaths{raw,err:=readSmall(p,snapshot.MaxSignatureBytes);if err!=nil{return err};s,err:=snapshot.DecodeSignature(raw);if err!=nil{return err};sigs=append(sigs,s)}
		raw,err:=readSnapshot(flags.Arg(0));if err!=nil{return err}
		report,err:=snapshot.InstallResearch(*dir,raw,sigs,options);if err!=nil{return err}
		return enc.Encode(report)
	}
	if flags.NArg()!=0||fp!=nil&&*fp==""{return errors.New("unexpected arguments or missing fingerprint")}
	v,report,err:=snapshot.LoadResearch(*dir,options);if err!=nil{return err}
	if fp==nil{return enc.Encode(report)}
	record,err:=v.Find(*fp);if err!=nil{return err}
	return enc.Encode(struct{Installation snapshot.InstallationReport `json:"installation"`;Certificate any `json:"certificate"`}{report,record})
}
