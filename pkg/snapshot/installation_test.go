package snapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
)

func TestInstallationLifecycle(t *testing.T){
	s,docs,o:=fixture(t)
	dir:=filepath.Join(t.TempDir(),"state")
	pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	build:=func(opts Options)([]byte,[]Signature){
		t.Helper()
		raw,_,err:=Build(s,docs,opts);if err!=nil{t.Fatal(err)}
		sig,err:=SignResearch(raw,key);if err!=nil{t.Fatal(err)}
		return raw,[]Signature{sig}
	}
	raw,sigs:=build(o)
	options:=InstallationOptions{Keys:[]ed25519.PublicKey{pub},Threshold:1,At:o.CreatedAt.Add(time.Hour)}
	if _,err:=InstallResearch(dir,raw,sigs,options);err==nil{t.Fatal("implicit bootstrap")}
	options.Bootstrap=true
	first,err:=InstallResearch(dir,raw,sigs,options)
	if err!=nil||first.Checkpoint.Sequence!=1||first.ReleaseAuthenticated||first.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("install: %+v %v",first,err)}
	if _,err:=InstallResearch(dir,raw,sigs,options);err==nil{t.Fatal("rebootstrap")}
	options.Bootstrap=false
	v,rep,err:=LoadResearch(dir,options)
	if err!=nil||rep.Checkpoint!=first.Checkpoint||rep.ReleaseAuthenticated{t.Fatalf("load: %+v %v",rep,err)}
	page,err:=v.Search(registry.Query{})
	if err!=nil||len(page.Certificates)!=1{t.Fatalf("query: %+v %v",page,err)}
	if _,err:=v.Find(page.Certificates[0].FingerprintSHA256);err!=nil{t.Fatal(err)}
	d,err:=v.Policy(docs[0].Policy.ID,1);if err!=nil{t.Fatal(err)}
	d.Policy.ID="modified"
	if _,err:=v.Policy(docs[0].Policy.ID,1);err!=nil{t.Fatal("mutated view")}
	if _,err:=v.Policy(docs[0].Policy.ID,2);err==nil{t.Fatal("unknown policy version")}
	repeat,err:=InstallResearch(dir,raw,sigs,options);if err!=nil||repeat.Status!="ALREADY_INSTALLED"{t.Fatalf("repeat: %+v %v",repeat,err)}
	conflict:=o;conflict.ExpiresAt=conflict.ExpiresAt.Add(time.Hour)
	cr,cs:=build(conflict)
	if _,err:=InstallResearch(dir,cr,cs,options);err==nil{t.Fatal("same-sequence conflict")}
	// Expired installed versions cannot load, but a fresh successor can replace them.
	options.At=o.ExpiresAt
	if _,_,err:=LoadResearch(dir,options);err==nil{t.Fatal("expired load")}
	next:=o;next.Sequence=2;next.CreatedAt=options.At;next.ExpiresAt=options.At.Add(time.Hour)
	nr,ns:=build(next)
	second,err:=InstallResearch(dir,nr,ns,options)
	if err!=nil||second.Checkpoint.Sequence!=2{t.Fatalf("update: %+v %v",second,err)}
	options.At=next.CreatedAt.Add(time.Minute)
	oldOpts:=o;oldOpts.ExpiresAt=next.ExpiresAt
	or,osigs:=build(oldOpts)
	if _,err:=InstallResearch(dir,or,osigs,options);err==nil{t.Fatal("rollback")}
	other,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	wrong:=options;wrong.Keys=[]ed25519.PublicKey{other}
	if _,_,err:=LoadResearch(dir,wrong);err==nil{t.Fatal("key config changed")}
	if err:=os.WriteFile(filepath.Join(dir,recordName(second.Checkpoint)),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	if _,_,err:=LoadResearch(dir,options);err==nil{t.Fatal("corrupt latest fallback")}
	if _,err:=InstallResearch(dir,nr,ns,options);err==nil{t.Fatal("corrupt latest update")}
}

func TestInstallationLockAndUnexpectedEntry(t *testing.T){
	dir:=t.TempDir()
	if err:=os.Mkdir(filepath.Join(dir,".lock"),0700);err!=nil{t.Fatal(err)}
	if err:=withInstallationLock(dir,false,func(string)error{t.Fatal("lock acquired");return nil});err==nil{t.Fatal("stale lock ignored")}
	if err:=os.Remove(filepath.Join(dir,".lock"));err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(filepath.Join(dir,".pending-crash"),[]byte("x"),0600);err!=nil{t.Fatal(err)}
	if err:=withInstallationLock(dir,false,func(root string)error{_,_,err:=latestRecord(root);return err});err==nil{t.Fatal("partial file ignored")}
}

func TestBootstrapAndLoadedPolicyPath(t *testing.T){
	s,docs,o:=fixture(t)
	pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	raw,_,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
	sig,err:=SignResearch(raw,key);if err!=nil{t.Fatal(err)}
	opts:=InstallationOptions{Keys:[]ed25519.PublicKey{pub},Threshold:1,At:o.CreatedAt.Add(time.Hour),Bootstrap:true}
	if _,err:=InstallResearch(t.TempDir(),raw,[]Signature{sig},opts);err==nil{t.Fatal("existing empty directory bootstrap")}
	dir:=filepath.Join(t.TempDir(),"new")
	bad:=sig;bad.Signature=append([]byte{},sig.Signature...);bad.Signature[0]^=1
	if _,err:=InstallResearch(dir,raw,[]Signature{bad},opts);err==nil{t.Fatal("bad signature")}
	if _,err:=os.Stat(dir);!os.IsNotExist(err){t.Fatal("bad bootstrap created state")}
	if _,err:=InstallResearch(dir,raw,[]Signature{sig},opts);err!=nil{t.Fatal(err)}
	opts.Bootstrap=false
	view,_,err:=LoadResearch(dir,opts);if err!=nil{t.Fatal(err)}
	leaf:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic end entity"},NotBefore:o.CreatedAt,NotAfter:o.ExpiresAt,KeyUsage:x509.KeyUsageDigitalSignature}
	der,err:=x509.CreateCertificate(rand.Reader,leaf,leaf,pub,key);if err!=nil{t.Fatal(err)}
	id,purpose:=docs[0].Policy.ID,docs[0].Policy.Purpose
	result,err:=view.VerifyLocalPath(der,id,1,purpose,"",opts.At,opts.At)
	if err!=nil||result.Path.PathStatus!="NOT_ESTABLISHED"||result.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("empty policy: %+v %v",result,err)}
	if _,err:=view.VerifyLocalPath(der,id,2,purpose,"",opts.At,opts.At);err==nil{t.Fatal("unknown version accepted")}
	if _,err:=view.VerifyLocalPath(der,id,1,"timestamping","",opts.At,opts.At);err==nil{t.Fatal("wrong purpose accepted")}
	if _,err:=view.VerifyLocalPath(der,id,1,purpose,"",opts.At,opts.At.Add(time.Hour));err==nil{t.Fatal("future knowledge accepted")}
}
