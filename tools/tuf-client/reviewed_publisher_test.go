package tufclient

import (
 "bytes"
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
 // Ledger commits exact signed metadata, with an independently retainable head.
 ledger:=filepath.Join(t.TempDir(),"publication")
 lo:=LedgerOptions{Directory:ledger,AuthoritySHA256:digest(ab),Reviewed:o}
 receipt,err:=BuildInLedger(root,raw,lo);if err!=nil||receipt.Sequence!=1||receipt.Status!="LOCAL_REVIEWED_BUILD_COMMITTED"{t.Fatal(receipt,err)}
 exported,er,err:=ExportLedgerHead(ledger,digest(root),digest(ab),receipt.RecordSHA256,now)
 if err!=nil||er.RecordSHA256!=receipt.RecordSHA256||len(exported.Files)!=5{t.Fatal(er,err)}
 for name,data:=range repo.Files{if !bytes.Equal(exported.Files[name],data){t.Fatal("changed export",name)}}
 if _,err:=BuildInLedger(root,raw,lo);err==nil{t.Fatal("repeat bootstrap")}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),strings.Repeat("b",64),now);err==nil{t.Fatal("wrong head pin")}
 if err:=os.Mkdir(filepath.Join(ledger,".lock"),0700);err!=nil{t.Fatal(err)}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),"",now);err==nil{t.Fatal("concurrent operation")}
 if err:=os.Remove(filepath.Join(ledger,".lock"));err!=nil{t.Fatal(err)}
 // Sequence two reuses inventory but needs a fresh signed approval.
 later:=now.Add(time.Minute)
 raw2,_,err:=snapshot.Build(s,nil,snapshot.Options{Sequence:2,SourceRevision:strings.Repeat("b",40),CreatedAt:later,ExpiresAt:now.Add(24*time.Hour)});if err!=nil{t.Fatal(err)}
 d2,err:=review.Plan(raw2);if err!=nil{t.Fatal(err)}
 for i:=range d2.Reviews{
  for _,v:=range d.Reviews{if d2.Reviews[i].Requirement.ID==v.Requirement.ID{d2.Reviews[i]=v;d2.Reviews[i].ReviewedAt=&later;break}}
 }
 a2,err:=review.NewApproval(raw2,d2,dir,a,later,later.Add(time.Hour));if err!=nil{t.Fatal(err)}
 for _,v:=range d2.Reviews{a2,err=review.SignReview(raw2,d2,dir,a,a2,v.Requirement.ID,reviewers[v.Reviewer],later);if err!=nil{t.Fatal(err)}}
 for _,id:=range []string{"release-a","release-b"}{a2,err=review.SignRelease(raw2,d2,dir,a,a2,id,reviewers[id],later);if err!=nil{t.Fatal(err)}}
 lo.Reviewed.Bootstrap=false;lo.Reviewed.Publish.Version=2;lo.Reviewed.Publish.Now=later;lo.Reviewed.Dossier=d2;lo.Reviewed.Approval=a2;lo.ExpectedHeadSHA256=receipt.RecordSHA256
 receipt2,err:=BuildInLedger(root,raw2,lo);if err!=nil||receipt2.Sequence!=2||receipt2.PreviousRecordSHA256!=receipt.RecordSHA256{t.Fatal(receipt2,err)}
 if _,err:=BuildInLedger(root,raw2,lo);err==nil{t.Fatal("stale head replay")}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),receipt2.RecordSHA256,now.Add(time.Hour));err==nil{t.Fatal("expired timestamp exported")}
 if err:=os.Remove(filepath.Join(ledger,evidenceName(1)));err!=nil{t.Fatal(err)}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),receipt2.RecordSHA256,later);err==nil{t.Fatal("gap ignored")}
 // A review key listed in ANY TUF role is rejected, even if not used to sign.
 opts.Roles[metadata.TARGETS]=RoleKeys{[]ed25519.PublicKey{reviewers["source"].Public().(ed25519.PublicKey)},1}
 badRoot,err:=CreateRoot(opts);if err!=nil{t.Fatal(err)}
 if err:=checkRoleSeparation(badRoot,digest(badRoot),a);err==nil{t.Fatal("cross-config role key reuse")}
}
