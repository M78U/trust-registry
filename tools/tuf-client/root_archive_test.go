package tufclient

import (
 "context"
 "crypto/ed25519"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/theupdateframework/go-tuf/v2/metadata"
)
func TestRootArchiveRotationInstall(t *testing.T){
 now:=time.Now().UTC().Truncate(time.Second)
 first,k1:=rotationFixture(t,now.Add(24*time.Hour))
 root1,err:=CreateRoot(first);if err!=nil{t.Fatal(err)}
 second,k2:=rotationFixture(t,now.Add(48*time.Hour))
 pin:=digest(root1)
 root2,_,err:=RotateRoot([][]byte{root1},pin,RotateRootOptions{Now:now,Next:second,OldSigners:first.Signers,ExpectedCurrentSHA256:pin});if err!=nil{t.Fatal(err)}
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 build:=func(chain [][]byte,seq int64,keys map[string]ed25519.PrivateKey)Repository{
  t.Helper()
  raw,_,err:=snapshot.Build(s,nil,snapshot.Options{Sequence:uint64(seq),SourceRevision:strings.Repeat("a",40),CreatedAt:now.Add(-time.Minute),ExpiresAt:now.Add(12*time.Hour)});if err!=nil{t.Fatal(err)}
  o:=PublishOptions{RootSHA256:digest(chain[len(chain)-1]),Version:seq,Now:now,TargetsExpires:now.Add(6*time.Hour),SnapshotExpires:now.Add(4*time.Hour),TimestampExpires:now.Add(time.Hour),TargetsSigners:[]ed25519.PrivateKey{keys[metadata.TARGETS]},SnapshotSigners:[]ed25519.PrivateKey{keys[metadata.SNAPSHOT]},TimestampSigners:[]ed25519.PrivateKey{keys[metadata.TIMESTAMP]}}
  repo,_,err:=BuildRotatedRepository(chain,pin,raw,o);if err!=nil{t.Fatal(err)};return repo
 }
 repo:=build([][]byte{root1},1,k1)
 var mu sync.RWMutex
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  mu.RLock();raw,ok:=repo.Files[strings.TrimPrefix(r.URL.Path,"/")];mu.RUnlock()
  if !ok{http.NotFound(w,r);return};_,_=w.Write(raw)
 }));defer server.Close()
 state:=filepath.Join(t.TempDir(),"state")
 o:=Options{StateDir:state,MetadataURL:server.URL+"/metadata",TargetsURL:server.URL+"/targets",InitialRootSHA256:pin,BootstrapRoot:root1}
 if _,_,err:=refresh(context.Background(),o,true,server.Client());err!=nil{t.Fatal(err)}
 // Simulate an old v1 installation without the archive, migrate exact pin.
 if err:=os.RemoveAll(filepath.Join(state,"roots"));err!=nil{t.Fatal(err)}
 o.BootstrapRoot=nil
 next:=build([][]byte{root1,root2},2,k2)
 mu.Lock();repo=next;mu.Unlock()
 if _,r,err:=refresh(context.Background(),o,true,server.Client());err!=nil||r.RootVersion!=2{t.Fatal(r,err)}
 view,r,err:=LoadInstalled(state,pin);if err!=nil||view==nil||r.RootVersion!=2||r.Registry.Manifest.Sequence!=2||r.ReleaseAuthenticated{t.Fatal(r,err)}
 raw,err:=readRegular(filepath.Join(state,"roots","2.root.json"),maxRoot);if err!=nil||digest(raw)!=digest(root2){t.Fatal(err)}
 if err:=os.Remove(filepath.Join(state,"roots","2.root.json"));err!=nil{t.Fatal(err)}
 if _,_,err:=LoadInstalled(state,pin);err==nil{t.Fatal("truncated root archive accepted")}
 if _,_,err:=refresh(context.Background(),o,true,server.Client());err==nil{t.Fatal("refresh trusted cache without root history")}
}
