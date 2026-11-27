package tufclient

import (
 "crypto/ecdsa"
 "crypto/ed25519"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/json"
 "math/big"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/review"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/theupdateframework/go-tuf/v2/metadata"
)
func TestReviewedPublication(t *testing.T){
 now:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 opts:=RootOptions{Expires:now.Add(48*time.Hour),Roles:map[string]RoleKeys{}}
 keys:=map[string]ed25519.PrivateKey{}
 for _,role:=range roles{
  pub,k,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  opts.Roles[role]=RoleKeys{[]ed25519.PublicKey{pub},1};keys[role]=k
 }
 opts.Signers=[]ed25519.PrivateKey{keys[metadata.ROOT]}
 root,err:=CreateRoot(opts);if err!=nil{t.Fatal(err)}
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 c:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic candidate"},NotBefore:now,NotAfter:now.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 der,err:=x509.CreateCertificate(rand.Reader,c,c,&k.PublicKey,k);if err!=nil{t.Fatal(err)}
 if _,err:=s.Import(der,"https://example.org/ca",now);err!=nil{t.Fatal(err)}
 raw,_,err:=snapshot.Build(s,nil,snapshot.Options{Sequence:1,SourceRevision:strings.Repeat("a",40),CreatedAt:now,ExpiresAt:now.Add(24*time.Hour)});if err!=nil{t.Fatal(err)}
 d,err:=review.Plan(raw);if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 cfg:=review.AuthorityConfig{SchemaVersion:"1",ReleaseThreshold:2,Keys:[]review.AuthorityKey{}}
 reviewers:=map[string]ed25519.PrivateKey{}
 for _,v:=range []struct{id,role string}{{"source","SOURCE_IDENTITY"},{"rights","REVIEW"},{"release-a","RELEASE"},{"release-b","RELEASE"}}{
  pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  cfg.Keys=append(cfg.Keys,review.AuthorityKey{ID:v.id,Role:v.role,PublicKey:pub});reviewers[v.id]=priv
 }
 ab,err:=json.Marshal(cfg);if err!=nil{t.Fatal(err)}
 a,err:=review.ParseAuthority(ab,digest(ab));if err!=nil{t.Fatal(err)}
 for i:=range d.Reviews{
  v:=&d.Reviews[i];v.Status="APPROVED";v.ReviewedAt=&now;v.Note="synthetic fixture";v.Reviewer="rights"
  kinds:=[]string{"REDISTRIBUTION_TERMS"}
  if v.Requirement.Kind=="SOURCE_IDENTITY"{v.Reviewer="source";kinds=[]string{"ISSUER_SOURCE","INDEPENDENT_FINGERPRINT"}}
  for _,kind:=range kinds{
   data:=[]byte("synthetic "+kind);h:=digest(data)
   if err:=os.WriteFile(filepath.Join(dir,h+".evidence"),data,0600);err!=nil{t.Fatal(err)}
   v.Evidence=append(v.Evidence,review.Artifact{Kind:kind,SHA256:h,Reference:"fixture"})
  }
 }
 approval,err:=review.NewApproval(raw,d,dir,a,now,now.Add(time.Hour));if err!=nil{t.Fatal(err)}
 o:=ReviewedPublishOptions{Publish:PublishOptions{RootSHA256:digest(root),Version:1,Now:now,TargetsExpires:now.Add(12*time.Hour),SnapshotExpires:now.Add(6*time.Hour),TimestampExpires:now.Add(time.Hour),TargetsSigners:[]ed25519.PrivateKey{keys[metadata.TARGETS]},SnapshotSigners:[]ed25519.PrivateKey{keys[metadata.SNAPSHOT]},TimestampSigners:[]ed25519.PrivateKey{keys[metadata.TIMESTAMP]}},Authority:a,Dossier:d,EvidenceDir:dir,Approval:approval,Bootstrap:true}
 if _,_,err:=BuildReviewedRepository(root,raw,o);err==nil{t.Fatal("unsigned approval")}
 for _,v:=range d.Reviews{approval,err=review.SignReview(raw,d,dir,a,approval,v.Requirement.ID,reviewers[v.Reviewer],now);if err!=nil{t.Fatal(err)}}
 for _,id:=range []string{"release-a","release-b"}{approval,err=review.SignRelease(raw,d,dir,a,approval,id,reviewers[id],now);if err!=nil{t.Fatal(err)}}
 o.Approval=approval
 repo,report,err:=BuildReviewedRepository(root,raw,o);if err!=nil||len(repo.Files)!=5||report.Status!="REVIEWED_LOCAL_PUBLICATION_CANDIDATE"||report.ReleaseAuthenticated||report.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(report,err)}
 bad:=o;bad.Bootstrap=false
 if _,_,err:=BuildReviewedRepository(root,raw,bad);err==nil{t.Fatal("missing baseline")}
 bad=o;bad.Publish.Now=now.Add(time.Hour)
 if _,_,err:=BuildReviewedRepository(root,raw,bad);err==nil{t.Fatal("expired approval")}
 // A review key listed in ANY TUF role is rejected, even if not used to sign.
 opts.Roles[metadata.TARGETS]=RoleKeys{[]ed25519.PublicKey{reviewers["source"].Public().(ed25519.PublicKey)},1}
 badRoot,err:=CreateRoot(opts);if err!=nil{t.Fatal(err)}
 if err:=checkRoleSeparation(badRoot,digest(badRoot),a);err==nil{t.Fatal("cross-config role key reuse")}
}
