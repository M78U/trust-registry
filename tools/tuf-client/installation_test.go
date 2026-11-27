package tufclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/M78U/trust-registry/pkg/snapshot"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestPublisherClientInstallRoundTrip(t *testing.T){
	now:=time.Now().UTC().Truncate(time.Second)
	rootOpts:=RootOptions{Expires:now.Add(48*time.Hour),Roles:map[string]RoleKeys{}}
	keys:=map[string]ed25519.PrivateKey{}
	for _,role:=range roles{
		pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
		rootOpts.Roles[role]=RoleKeys{[]ed25519.PublicKey{pub},1};keys[role]=priv
	}
	rootOpts.Signers=[]ed25519.PrivateKey{keys[metadata.ROOT]}
	rb,err:=CreateRoot(rootOpts);if err!=nil{t.Fatal(err)}
	s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
	if _,err:=s.Init();err!=nil{t.Fatal(err)}
	build:=func(seq uint64)Repository{
		t.Helper()
		raw,_,err:=snapshot.Build(s,nil,snapshot.Options{Sequence:seq,SourceRevision:strings.Repeat("a",40),CreatedAt:now.Add(-time.Minute),ExpiresAt:now.Add(24*time.Hour)});if err!=nil{t.Fatal(err)}
		repo,err:=BuildRepository(rb,raw,PublishOptions{RootSHA256:digest(rb),Version:int64(seq),Now:now,TargetsExpires:now.Add(12*time.Hour),SnapshotExpires:now.Add(6*time.Hour),TimestampExpires:now.Add(time.Hour),TargetsSigners:[]ed25519.PrivateKey{keys[metadata.TARGETS]},SnapshotSigners:[]ed25519.PrivateKey{keys[metadata.SNAPSHOT]},TimestampSigners:[]ed25519.PrivateKey{keys[metadata.TIMESTAMP]}});if err!=nil{t.Fatal(err)}
		return repo
	}
	repo:=build(1)
	// No external network or real keys. TLS server transport only through
	// the private test seam, not the public API.
	server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		b,ok:=repo.Files[strings.TrimPrefix(r.URL.Path,"/")]
		if !ok{http.NotFound(w,r);return}
		_,_ = w.Write(b)
	}));defer server.Close()
	state:=filepath.Join(t.TempDir(),"state")
	o:=Options{StateDir:state,MetadataURL:server.URL+"/metadata",TargetsURL:server.URL+"/targets",InitialRootSHA256:digest(rb),BootstrapRoot:rb}
	_,r,err:=refresh(context.Background(),o,true,server.Client())
	if err!=nil||!r.TUFTargetAuthenticated||r.ReleaseAuthenticated||r.Registry.Manifest.Sequence!=1{t.Fatalf("install: %+v %v",r,err)}
	v,r,err:=LoadInstalled(state,digest(rb))
	if err!=nil||v==nil||r.Registry.Manifest.Sequence!=1{t.Fatalf("load: %+v %v",r,err)}
	o.BootstrapRoot=nil
	repo=build(2)
	if _,_,err:=refresh(context.Background(),o,true,server.Client());err!=nil{t.Fatal(err)}
	_,r,err=LoadInstalled(state,digest(rb));if err!=nil||r.Registry.Manifest.Sequence!=2{t.Fatalf("update: %+v %v",r,err)}
	repo=build(1)
	if _,_,err:=refresh(context.Background(),o,true,server.Client());err==nil{t.Fatal("rollback accepted")}
	if err:=os.WriteFile(filepath.Join(state,"installed",evidenceName(2)),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	if _,_,err:=LoadInstalled(state,digest(rb));err==nil{t.Fatal("corrupt newest fallback")}
}
