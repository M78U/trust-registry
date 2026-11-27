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
	var policyID,purpose,dns,evaluation,known string
	var version int
	switch args[0]{
	case "install-research":
		flags.Func("signature","detached signature JSON",add(&sigPaths))
		bootstrap=flags.Bool("bootstrap",false,"explicit first installation")
	case "find-installed":
		fp=flags.String("fingerprint","","certificate DER SHA-256")
	case "verify-installed-path":
		flags.StringVar(&policyID,"policy-id","","exact installed policy ID")
		flags.IntVar(&version,"policy-version",0,"exact installed policy version")
		flags.StringVar(&purpose,"purpose","","explicit policy purpose")
		flags.StringVar(&dns,"dns-name","","server authentication DNS name")
		flags.StringVar(&evaluation,"evaluation-time","","certificate evaluation time RFC3339")
		flags.StringVar(&known,"known-at","","policy knowledge cutoff RFC3339")
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
	if args[0]=="verify-installed-path"{
		if flags.NArg()!=1||policyID==""||version<1||purpose==""||evaluation==""||known==""{return errors.New("certificate, policy-id, policy-version, purpose, evaluation-time and known-at required")}
		e,err:=time.Parse(time.RFC3339Nano,evaluation);if err!=nil{return err}
		k,err:=time.Parse(time.RFC3339Nano,known);if err!=nil{return err}
		input,err:=readInput(flags.Arg(0));if err!=nil{return err}
		v,report,err:=snapshot.LoadResearch(*dir,options);if err!=nil{return err}
		result,err:=v.VerifyLocalPath(input,policyID,version,purpose,dns,e.UTC(),k.UTC());if err!=nil{return err}
		if err:=enc.Encode(struct{Installation snapshot.InstallationReport `json:"installation"`;Result any `json:"result"`}{report,result});err!=nil{return err}
		if result.Path.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"{return errors.New("no valid technical path under installed research policy")}
		return nil
	}
	if flags.NArg()!=0||fp!=nil&&*fp==""{return errors.New("unexpected arguments or missing fingerprint")}
	v,report,err:=snapshot.LoadResearch(*dir,options);if err!=nil{return err}
	if fp==nil{return enc.Encode(report)}
	record,err:=v.Find(*fp);if err!=nil{return err}
	return enc.Encode(struct{Installation snapshot.InstallationReport `json:"installation"`;Certificate any `json:"certificate"`}{report,record})
}
