package review

import(
 "crypto/ecdsa"
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

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/snapshot"
)
func reviewFixture(t *testing.T)([]byte,time.Time){
 t.Helper()
 at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 c:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic review CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 der,err:=x509.CreateCertificate(rand.Reader,c,c,&k.PublicKey,k);if err!=nil{t.Fatal(err)}
 row,err:=s.Import(der,"https://example.org/ca",at);if err!=nil{t.Fatal(err)}
 if _,err:=s.Import(der,"https://example.org/second",at);err!=nil{t.Fatal(err)}
 d:=policy.Document{Policy:policy.Defaults()[0],Reviews:[]policy.Review{},Decisions:[]policy.Decision{}}
 d.Policy.TrustAnchors=[]string{row.Certificate.FingerprintSHA256}
 raw,_,err:=snapshot.Build(s,[]policy.Document{d},snapshot.Options{Sequence:1,SourceRevision:strings.Repeat("a",40),CreatedAt:at,ExpiresAt:at.Add(time.Hour)});if err!=nil{t.Fatal(err)}
 return raw,at
}
func TestReviewGate(t *testing.T){
 raw,at:=reviewFixture(t);dir:=t.TempDir()
 d,err:=Plan(raw);if err!=nil||len(d.Reviews)!=6{t.Fatal(d,err)}
 b,err:=json.MarshalIndent(d,"","  ");if err!=nil{t.Fatal(err)}
 d,err=DecodeDossier(b);if err!=nil{t.Fatal(err)}
 r,err:=Check(raw,d,dir,at);if err!=nil||r.Status!="BLOCKED"||len(r.Findings)!=6{t.Fatal(r,err)}
 for i:=range d.Reviews{
  v:=&d.Reviews[i];v.Status="APPROVED";v.Reviewer="reviewer-b";if v.Requirement.Kind=="SOURCE_IDENTITY"{v.Reviewer="reviewer-a"}
  v.ReviewedAt=&at;v.Note="synthetic approval"
  for _,kind:=range artifactKinds(v.Requirement.Kind){
   payload:=[]byte("synthetic "+kind)
   h:=digest(payload);if err:=os.WriteFile(filepath.Join(dir,h+".evidence"),payload,0600);err!=nil{t.Fatal(err)}
   v.Evidence=append(v.Evidence,Artifact{kind,h,"fixture"})
  }
 }
 r,err=Check(raw,d,dir,at);if err!=nil||r.Status!="LOCAL_REVIEW_REQUIREMENTS_SATISFIED"||r.Approved!=6||r.VerifiedArtifactFiles!=5||r.ReleaseAuthorized||r.ReleaseAuthenticated||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(r,err)}
 clone:=func()Dossier{b,_:=canonical(d);v,err:=DecodeDossier(b);if err!=nil{t.Fatal(err)};return v}
 v:=clone();v.SnapshotSHA256=strings.Repeat("b",64);if _,err:=Check(raw,v,dir,at);err==nil{t.Fatal("wrong snapshot")}
 v=clone();v.Reviews=v.Reviews[1:];if _,err:=Check(raw,v,dir,at);err==nil{t.Fatal("omission")}
 v=clone();v.Reviews[0].Requirement.Purpose="other";if _,err:=Check(raw,v,dir,at);err==nil{t.Fatal("altered task")}
 v=clone();for i:=range v.Reviews{v.Reviews[i].Reviewer="same"};r,err=Check(raw,v,dir,at);if err!=nil||r.Status!="BLOCKED"||len(r.Findings)!=3{t.Fatal(r,err)}
 v=clone();v.Reviews[0].Status="REJECTED";r,err=Check(raw,v,dir,at);if err!=nil||r.Status!="BLOCKED"{t.Fatal(r,err)}
 v=clone();future:=at.Add(time.Minute);v.Reviews[0].ReviewedAt=&future;if _,err:=Check(raw,v,dir,at);err==nil{t.Fatal("future review")}
 if _,err:=Check(raw,d,dir,at.Add(time.Hour));err==nil{t.Fatal("expired snapshot")}
 if err:=os.WriteFile(filepath.Join(dir,d.Reviews[0].Evidence[0].SHA256+".evidence"),[]byte("altered"),0600);err!=nil{t.Fatal(err)}
 if _,err:=Check(raw,d,dir,at);err==nil{t.Fatal("altered evidence")}
 if _,err:=DecodeDossier([]byte(`{"schemaVersion":"1","schemaVersion":"1","snapshotSHA256":"`+strings.Repeat("a",64)+`","reviews":[]}`));err==nil{t.Fatal("duplicate JSON key")}
}
