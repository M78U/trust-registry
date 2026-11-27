package tufclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/M78U/trust-registry/pkg/snapshot"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestPublisherSignedMetadata(t *testing.T){
	now:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	o:=RootOptions{Expires:now.Add(48*time.Hour),Roles:map[string]RoleKeys{}}
	keys:=map[string]ed25519.PrivateKey{}
	for _,role:=range roles{
		pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
		o.Roles[role]=RoleKeys{[]ed25519.PublicKey{pub},1};keys[role]=priv
	}
	o.Signers=[]ed25519.PrivateKey{keys[metadata.ROOT]}
	rb,err:=CreateRoot(o);if err!=nil{t.Fatal(err)}
	rb2,err:=CreateRoot(o);if err!=nil||string(rb)!=string(rb2){t.Fatal("root not deterministic")}
	bad:=o;bad.Roles=map[string]RoleKeys{}
	for k,v:=range o.Roles{bad.Roles[k]=v}
	bad.Roles[metadata.TIMESTAMP]=bad.Roles[metadata.ROOT]
	if _,err:=CreateRoot(bad);err==nil{t.Fatal("shared role key accepted")}
	store,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
	if _,err:=store.Init();err!=nil{t.Fatal(err)}
	raw,_,err:=snapshot.Build(store,nil,snapshot.Options{Sequence:1,SourceRevision:strings.Repeat("a",40),CreatedAt:now,ExpiresAt:now.Add(24*time.Hour)});if err!=nil{t.Fatal(err)}
	p:=PublishOptions{RootSHA256:digest(rb),Version:1,Now:now,TargetsExpires:now.Add(12*time.Hour),SnapshotExpires:now.Add(6*time.Hour),TimestampExpires:now.Add(time.Hour),TargetsSigners:[]ed25519.PrivateKey{keys[metadata.TARGETS]},SnapshotSigners:[]ed25519.PrivateKey{keys[metadata.SNAPSHOT]},TimestampSigners:[]ed25519.PrivateKey{keys[metadata.TIMESTAMP]}}
	repo,err:=BuildRepository(rb,raw,p);if err!=nil{t.Fatal(err)}
	if len(repo.Files)!=5{t.Fatal("unexpected repository files")}
	root,err:=metadata.Root().FromBytes(repo.Files["metadata/1.root.json"]);if err!=nil{t.Fatal(err)}
	tg,err:=metadata.Targets().FromBytes(repo.Files["metadata/1.targets.json"]);if err!=nil{t.Fatal(err)}
	sn,err:=metadata.Snapshot().FromBytes(repo.Files["metadata/1.snapshot.json"]);if err!=nil{t.Fatal(err)}
	ts,err:=metadata.Timestamp().FromBytes(repo.Files["metadata/timestamp.json"]);if err!=nil{t.Fatal(err)}
	for _,v:=range []struct{role string;m any}{{metadata.ROOT,root},{metadata.TARGETS,tg},{metadata.SNAPSHOT,sn},{metadata.TIMESTAMP,ts}}{if err:=root.VerifyDelegate(v.role,v.m);err!=nil{t.Fatal(err)}}
	if err:=ts.Signed.Meta["snapshot.json"].VerifyLengthHashes(repo.Files["metadata/1.snapshot.json"]);err!=nil{t.Fatal(err)}
	if err:=sn.Signed.Meta["targets.json"].VerifyLengthHashes(repo.Files["metadata/1.targets.json"]);err!=nil{t.Fatal(err)}
	if err:=tg.Signed.Targets[TargetName].VerifyLengthHashes(repo.Files["targets/"+digest(raw)+"."+TargetName]);err!=nil{t.Fatal(err)}
	p.Version=2
	if _,err:=BuildRepository(rb,raw,p);err==nil{t.Fatal("sequence mismatch accepted")}
	p.Version=1;p.TargetsSigners=p.TimestampSigners
	if _,err:=BuildRepository(rb,raw,p);err==nil{t.Fatal("unauthorized signer accepted")}
}
