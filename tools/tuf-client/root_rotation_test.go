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
func rotationFixture(t *testing.T,expiry time.Time)(RootOptions,map[string]ed25519.PrivateKey){
 t.Helper()
 o:=RootOptions{Expires:expiry,Roles:map[string]RoleKeys{}}
 keys:=map[string]ed25519.PrivateKey{}
 for _,role:=range roles{
  pub,k,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  o.Roles[role]=RoleKeys{[]ed25519.PublicKey{pub},1};keys[role]=k
 }
 o.Signers=[]ed25519.PrivateKey{keys[metadata.ROOT]}
 return o,keys
}
func TestRootRotationAndOfflineRepository(t *testing.T){
 at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 initial,k1:=rotationFixture(t,at.Add(time.Hour))
 root1,err:=CreateRoot(initial);if err!=nil{t.Fatal(err)}
 next,k2:=rotationFixture(t,at.Add(48*time.Hour))
 chain:=[][]byte{root1};pin:=digest(root1)
 opt:=RotateRootOptions{Now:at,Next:next,OldSigners:initial.Signers,ExpectedCurrentSHA256:pin}
 bad:=opt;bad.OldSigners=next.Signers
 if _,_,err:=RotateRoot(chain,pin,bad);err==nil{t.Fatal("new signatures alone accepted")}
 bad=opt;bad.Next.Signers=initial.Signers
 if _,_,err:=RotateRoot(chain,pin,bad);err==nil{t.Fatal("old signatures alone accepted")}
 bad=opt;bad.ExpectedCurrentSHA256=strings.Repeat("a",64)
 if _,_,err:=RotateRoot(chain,pin,bad);err==nil{t.Fatal("stale head accepted")}
 root2,r,err:=RotateRoot(chain,pin,opt);if err!=nil||r.RootVersion!=2||r.CurrentRootSHA256!=digest(root2){t.Fatal(r,err)}
 chain=append(chain,root2)
 // A client may update through an expired intermediate root.
 later:=at.Add(2*time.Hour)
 if _,err:=VerifyRootChain(chain,pin,later);err!=nil{t.Fatal(err)}
 if _,err:=VerifyRootChain(chain[:1],pin,later);err==nil{t.Fatal("expired final root")}
 third,_:=rotationFixture(t,at.Add(72*time.Hour))
 root3,_,err:=RotateRoot(chain,pin,RotateRootOptions{Now:later,Next:third,OldSigners:next.Signers,ExpectedCurrentSHA256:digest(root2)});if err!=nil{t.Fatal(err)}
 if _,err:=VerifyRootChain([][]byte{root1,root3},pin,later);err==nil{t.Fatal("skipped root accepted")}
 if _,err:=VerifyRootChain([][]byte{root1,root2,root1},pin,later);err==nil{t.Fatal("root rollback")}
 if _,err:=VerifyRootChain([][]byte{root2},digest(root2),later);err==nil{t.Fatal("rotated root as bootstrap")}
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 raw,_,err:=snapshot.Build(s,nil,snapshot.Options{Sequence:2,SourceRevision:strings.Repeat("a",40),CreatedAt:later,ExpiresAt:later.Add(12*time.Hour)});if err!=nil{t.Fatal(err)}
 o:=PublishOptions{RootSHA256:digest(root2),Version:2,Now:later,TargetsExpires:later.Add(6*time.Hour),SnapshotExpires:later.Add(4*time.Hour),TimestampExpires:later.Add(time.Hour),TargetsSigners:[]ed25519.PrivateKey{k2[metadata.TARGETS]},SnapshotSigners:[]ed25519.PrivateKey{k2[metadata.SNAPSHOT]},TimestampSigners:[]ed25519.PrivateKey{k2[metadata.TIMESTAMP]}}
 if _,err:=BuildRepository(root2,raw,o);err==nil{t.Fatal("v1 builder accepted rotated root")}
 repo,rr,err:=BuildRotatedRepository(chain,pin,raw,o);if err!=nil||len(repo.Files)!=6||rr.RootVersion!=2{t.Fatal(rr,err)}
 report,err:=VerifyRotatedRepository(chain,pin,digest(root2),repo,later);if err!=nil||!report.TUFTargetAuthenticated||report.RootVersion!=2||report.ReleaseAuthenticated||report.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(report,err)}
 o.TargetsSigners=[]ed25519.PrivateKey{k1[metadata.TARGETS]}
 if _,_,err:=BuildRotatedRepository(chain,pin,raw,o);err==nil{t.Fatal("retired targets signer accepted")}
 if _,err:=VerifyRotatedRepository(chain,pin,pin,repo,later);err==nil{t.Fatal("wrong current pin")}
 repo.Files["metadata/timestamp.json"]=[]byte("{}")
 if _,err:=VerifyRotatedRepository(chain,pin,digest(root2),repo,later);err==nil{t.Fatal("tampered timestamp")}
}
