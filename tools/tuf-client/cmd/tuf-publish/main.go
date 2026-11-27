package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tuf "github.com/M78U/trust-registry/tools/tuf-client"
	"github.com/M78U/trust-registry/pkg/snapshot"
	"github.com/M78U/trust-registry/pkg/review"
)
type paths []string
func (p *paths) String()string{return strings.Join(*p,",")}
func (p *paths) Set(v string)error{if v==""||len(*p)>=16{return errors.New("invalid key path or count")};*p=append(*p,v);return nil}

func read(path string,limit int64)([]byte,error){
	i,err:=os.Lstat(path);if err!=nil{return nil,err}
	if !i.Mode().IsRegular()||i.Size()>limit{return nil,errors.New("invalid input file type or size")}
	f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
	st,err:=f.Stat();if err!=nil{return nil,err}
	if !os.SameFile(i,st){return nil,errors.New("input changed while opening")}
	b,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err}
	if int64(len(b))>limit{return nil,errors.New("input too large")}
	return b,nil
}
func keyDER(path,kind string)([]byte,error){
	raw,err:=read(path,16384);if err!=nil{return nil,err};defer clear(raw)
	p,rest:=pem.Decode(raw)
	if p==nil||p.Type!=kind||len(p.Headers)!=0||len(bytes.TrimSpace(rest))!=0||!bytes.HasPrefix(bytes.TrimSpace(raw),[]byte("-----BEGIN "+kind+"-----")){return nil,errors.New("invalid PEM key")}
	return p.Bytes,nil
}
func public(p paths)([]ed25519.PublicKey,error){
	out:=[]ed25519.PublicKey{}
	for _,path:=range p{b,err:=keyDER(path,"PUBLIC KEY");if err!=nil{return nil,err};k,err:=x509.ParsePKIXPublicKey(b);if err!=nil{return nil,err};pub,ok:=k.(ed25519.PublicKey);if !ok{return nil,errors.New("Ed25519 public key required")};out=append(out,pub)}
	return out,nil
}
func private(p paths)([]ed25519.PrivateKey,error){
	out:=[]ed25519.PrivateKey{}
	for _,path:=range p{b,err:=keyDER(path,"PRIVATE KEY");if err!=nil{return nil,err};k,err:=x509.ParsePKCS8PrivateKey(b);clear(b);if err!=nil{return nil,errors.New("invalid PKCS#8 private key")};priv,ok:=k.(ed25519.PrivateKey);if !ok{return nil,errors.New("Ed25519 private key required")};out=append(out,priv)}
	return out,nil
}
func wipe(keys []ed25519.PrivateKey){for _,k:=range keys{clear(k)}}
func instant(s string)(time.Time,error){t,err:=time.Parse(time.RFC3339Nano,s);return t.UTC(),err}
func writeNew(path string,b []byte)error{
	f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
	if _,err=f.Write(b);err==nil{err=f.Sync()};e:=f.Close();if err==nil{err=e};if err!=nil{_ = os.Remove(path)};return err
}
func run(args []string)error{
	if len(args)==0{return errors.New("usage: tuf-publish root | rotate-root | verify-root-chain | build | build-rotated | build-reviewed | build-ledger | ledger-export")}
	f:=flag.NewFlagSet(args[0],flag.ContinueOnError)
	out:=f.String("out","","new output file or directory")
	switch args[0]{
	case "root":
		exp:=f.String("expires","","root expiry RFC3339")
		type roleFlags struct{pub paths;threshold *int}
		all:=map[string]*roleFlags{}
		for _,role:=range []string{"root","targets","snapshot","timestamp"}{v:=&roleFlags{};f.Var(&v.pub,role+"-public","repeatable SPKI PEM");v.threshold=f.Int(role+"-threshold",1,"role threshold");all[role]=v}
		var signer paths;f.Var(&signer,"root-key","repeatable root PKCS#8 PEM")
		if err:=f.Parse(args[1:]);err!=nil{return err}
		if f.NArg()!=0||*out==""||*exp==""{return errors.New("root output and expiry required")}
		t,err:=instant(*exp);if err!=nil{return err}
		o:=tuf.RootOptions{Expires:t,Roles:map[string]tuf.RoleKeys{}}
		for role,v:=range all{keys,err:=public(v.pub);if err!=nil{return err};o.Roles[role]=tuf.RoleKeys{PublicKeys:keys,Threshold:*v.threshold}}
		o.Signers,err=private(signer);if err!=nil{return err};defer wipe(o.Signers)
		raw,err:=tuf.CreateRoot(o);if err!=nil{return err}
		return writeNew(*out,raw)
	case "rotate-root","verify-root-chain":
		return runRotation(args[0],f,args[1:],out)
	case "ledger-export":
		return exportLedger(f,args[1:],out)
	case "build","build-rotated","build-reviewed","build-ledger":
		root:=f.String("root","","initial root metadata file")
		pin:=f.String("root-sha256","","independently verified root hash")
		ver:=f.Int64("version",0,"metadata version matching snapshot sequence")
		now:=f.String("now","","publication time RFC3339")
		te:=f.String("targets-expires","","targets expiration")
		se:=f.String("snapshot-expires","","snapshot expiration")
		tse:=f.String("timestamp-expires","","timestamp expiration")
		var dossierPath,evidenceDir,authorityPath,authorityPin,approvalPath,previousPath,previousPin string
		var bootstrap bool
		var chainPaths rootPaths
		var initialPin string
		if args[0]=="build-rotated"{f.Var(&chainPaths,"root-chain","numbered root files in order (repeatable)");f.StringVar(&initialPin,"initial-root-sha256","","independent v1 root pin")}
		var ledgerDir,expectedHead string
		if args[0]=="build-ledger"{
			f.StringVar(&ledgerDir,"ledger","","private publication ledger directory")
			f.StringVar(&expectedHead,"expected-head","","optional independently retained record pin")
		}
		if args[0]=="build-reviewed"||args[0]=="build-ledger"{
			f.StringVar(&dossierPath,"dossier","","complete local review dossier")
			f.StringVar(&evidenceDir,"evidence","","private evidence directory")
			f.StringVar(&authorityPath,"authority","","independent role key configuration")
			f.StringVar(&authorityPin,"authority-sha256","","independent authority pin")
			f.StringVar(&approvalPath,"approval","","canonical threshold approval")
			f.StringVar(&previousPath,"previous","","previous accepted snapshot")
			f.StringVar(&previousPin,"previous-sha256","","independently verified previous snapshot pin")
			f.BoolVar(&bootstrap,"bootstrap",false,"explicit first sequence bootstrap")
		}
		var tk,sk,ts paths
		f.Var(&tk,"targets-key","repeatable targets PKCS#8 PEM");f.Var(&sk,"snapshot-key","repeatable snapshot PKCS#8 PEM");f.Var(&ts,"timestamp-key","repeatable timestamp PKCS#8 PEM")
		if err:=f.Parse(args[1:]);err!=nil{return err}
		if f.NArg()!=1||*root==""||*pin==""||args[0]!="build-ledger"&&*out==""||args[0]=="build-ledger"&&(*out!=""||ledgerDir==""){return errors.New("root, pin, one snapshot and output (or ledger only in build-ledger) required")}
		o:=tuf.PublishOptions{RootSHA256:*pin,Version:*ver}
		var err error
		for _,v:=range []struct{s string;t *time.Time}{{*now,&o.Now},{*te,&o.TargetsExpires},{*se,&o.SnapshotExpires},{*tse,&o.TimestampExpires}}{*v.t,err=instant(v.s);if err!=nil{return err}}
		o.TargetsSigners,err=private(tk);if err!=nil{return err};defer wipe(o.TargetsSigners)
		o.SnapshotSigners,err=private(sk);if err!=nil{return err};defer wipe(o.SnapshotSigners)
		o.TimestampSigners,err=private(ts);if err!=nil{return err};defer wipe(o.TimestampSigners)
		rb,err:=read(*root,512000);if err!=nil{return err}
		raw,err:=read(f.Arg(0),snapshot.MaxEnvelopeBytes);if err!=nil{return err}
		var repo tuf.Repository
		var reviewed *tuf.ReviewedPublicationReport
		if args[0]=="build-reviewed"||args[0]=="build-ledger"{
			if dossierPath==""||evidenceDir==""||authorityPath==""||authorityPin==""||approvalPath==""{return errors.New("reviewed mode requires dossier, evidence, authority pin and approval")}
			if args[0]=="build-ledger"{if previousPath!=""||previousPin!=""{return errors.New("ledger selects previous baseline automatically")}}else if bootstrap&&(previousPath!=""||previousPin!="")||!bootstrap&&(previousPath==""||previousPin==""){return errors.New("explicit bootstrap or previous snapshot and independent pin required")}
			db,err:=read(dossierPath,review.MaxDossierBytes);if err!=nil{return err}
			d,err:=review.DecodeDossier(db);if err!=nil{return err}
			ab,err:=read(authorityPath,review.MaxAuthorityBytes);if err!=nil{return err}
			a,err:=review.ParseAuthority(ab,authorityPin);if err!=nil{return err}
			vb,err:=read(approvalPath,review.MaxApprovalBytes);if err!=nil{return err}
			v,err:=review.DecodeApproval(vb);if err!=nil{return err}
			var previous []byte
			if args[0]=="build-reviewed"&&!bootstrap{previous,err=read(previousPath,snapshot.MaxEnvelopeBytes);if err!=nil{return err}}
			options:=tuf.ReviewedPublishOptions{Publish:o,Authority:a,Dossier:d,EvidenceDir:evidenceDir,Approval:v,PreviousSnapshot:previous,PreviousSHA256:previousPin,Bootstrap:bootstrap}
			if args[0]=="build-ledger"{
				receipt,err:=tuf.BuildInLedger(rb,raw,tuf.LedgerOptions{Directory:ledgerDir,AuthoritySHA256:authorityPin,ExpectedHeadSHA256:expectedHead,Reviewed:options});if err!=nil{return err}
				return json.NewEncoder(os.Stdout).Encode(receipt)
			}
			result,report,err:=tuf.BuildReviewedRepository(rb,raw,options);if err!=nil{return err}
			repo=result;reviewed=&report
		}else if args[0]=="build-rotated"{
			chain,err:=loadRootChain(chainPaths);if err!=nil{return err}
			if !bytes.Equal(rb,chain[len(chain)-1]){return errors.New("root does not match final chain element")}
			repo,_,err=tuf.BuildRotatedRepository(chain,initialPin,raw,o);if err!=nil{return err}
		}else{repo,err=tuf.BuildRepository(rb,raw,o);if err!=nil{return err}}
		// Output is a fresh local staging directory, not a live repository.
		if err:=os.Mkdir(*out,0700);err!=nil{return err}
		for _,dir:=range []string{"metadata","targets"}{if err:=os.Mkdir(filepath.Join(*out,dir),0700);err!=nil{return err}}
		names:=[]string{}
		for name:=range repo.Files{names=append(names,name)}
		sort.Strings(names)
		for _,name:=range names{if err:=writeNew(filepath.Join(*out,filepath.FromSlash(name)),repo.Files[name]);err!=nil{return err}}
		if reviewed!=nil{return json.NewEncoder(os.Stdout).Encode(reviewed)}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status":"LOCAL_RESEARCH_PUBLICATION_CANDIDATE","rootSHA256":repo.RootSHA256,"targetSHA256":repo.TargetSHA256,"version":repo.Version,"files":names,"releaseAuthenticated":false,"trustStatus":"NOT_ESTABLISHED"})
	default:return errors.New("unknown publisher command")
	}
}
func main(){if err:=run(os.Args[1:]);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
