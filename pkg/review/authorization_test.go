package review

import(
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func TestAuthenticatedReviewAndThreshold(t *testing.T){
 raw,at:=reviewFixture(t);dir:=t.TempDir()
 d,err:=Plan(raw);if err!=nil{t.Fatal(err)}
 config:=AuthorityConfig{SchemaVersion:"1",ReleaseThreshold:2,Keys:[]AuthorityKey{}}
 keys:=map[string]ed25519.PrivateKey{}
 for _,entry:=range []struct{id,role string}{{"identity","SOURCE_IDENTITY"},{"rights","REVIEW"},{"release-a","RELEASE"},{"release-b","RELEASE"}}{
  pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  config.Keys=append(config.Keys,AuthorityKey{entry.id,entry.role,pub});keys[entry.id]=key
 }
 configRaw,err:=json.Marshal(config);if err!=nil{t.Fatal(err)}
 a,err:=ParseAuthority(configRaw,digest(configRaw));if err!=nil{t.Fatal(err)}
 if _,err:=ParseAuthority(configRaw,strings.Repeat("a",64));err==nil{t.Fatal("wrong authority pin")}
 bad:=config;bad.Keys=append([]AuthorityKey{},config.Keys...);bad.Keys[1].PublicKey=bad.Keys[0].PublicKey
 b,_:=json.Marshal(bad);if _,err:=ParseAuthority(b,digest(b));err==nil{t.Fatal("role key reuse")}
 for i:=range d.Reviews{
  row:=&d.Reviews[i];row.Status="APPROVED";row.Reviewer="rights";if row.Requirement.Kind=="SOURCE_IDENTITY"{row.Reviewer="identity"}
  row.ReviewedAt=&at;row.Note="synthetic fixture"
  for _,kind:=range artifactKinds(row.Requirement.Kind){
   data:=[]byte("fixture "+kind);h:=digest(data)
   if err:=os.WriteFile(filepath.Join(dir,h+".evidence"),data,0600);err!=nil{t.Fatal(err)}
   row.Evidence=append(row.Evidence,Artifact{kind,h,"fixture"})
  }
 }
 v,err:=NewApproval(raw,d,dir,a,at,at.Add(30*time.Minute));if err!=nil{t.Fatal(err)}
 if _,err:=SignRelease(raw,d,dir,a,v,"release-a",keys["release-a"],at);err==nil{t.Fatal("missing review signatures")}
 first:=d.Reviews[0]
 if _,err:=SignReview(raw,d,dir,a,v,first.Requirement.ID,keys["release-a"],at);err==nil{t.Fatal("release key used for review")}
 for _,row:=range d.Reviews{
  v,err=SignReview(raw,d,dir,a,v,row.Requirement.ID,keys[row.Reviewer],at);if err!=nil{t.Fatal(err)}
 }
 if _,err:=SignRelease(raw,d,dir,a,v,"rights",keys["rights"],at);err==nil{t.Fatal("review key used for release")}
 v,err=SignRelease(raw,d,dir,a,v,"release-a",keys["release-a"],at);if err!=nil{t.Fatal(err)}
 if _,err:=Authenticate(raw,d,dir,a,v,at);err==nil{t.Fatal("threshold bypass")}
 if _,err:=SignRelease(raw,d,dir,a,v,"release-a",keys["release-a"],at);err==nil{t.Fatal("duplicate signer")}
 v,err=SignRelease(raw,d,dir,a,v,"release-b",keys["release-b"],at);if err!=nil{t.Fatal(err)}
 data,err:=ApprovalBytes(v);if err!=nil{t.Fatal(err)}
 v,err=DecodeApproval(data);if err!=nil{t.Fatal(err)}
 r,err:=Authenticate(raw,d,dir,a,v,at);if err!=nil||!r.LocalReleaseApprovalVerified||r.ReleaseAuthorized||r.ReleaseAuthenticated||r.VerifiedReviewCount!=len(d.Reviews)||len(r.ReleaseApprovers)!=2||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(r,err)}
 clone:=func()Approval{v,e:=DecodeApproval(data);if e!=nil{t.Fatal(e)};return v}
 for _,kind:=range []string{"review","release","window","sequence","dossier","authority","omit"}{
  x:=clone()
  switch kind{case "review":x.Reviews[0].Signature[0]^=1;case "release":x.Releases[0].Signature[0]^=1;case "window":x.ApprovedUntil=x.ApprovedUntil.Add(time.Minute);case "sequence":x.Sequence++;case "dossier":x.DossierSHA256=strings.Repeat("b",64);case "authority":x.AuthoritySHA256=strings.Repeat("c",64);case "omit":x.Reviews=x.Reviews[1:]}
  if _,err:=Authenticate(raw,d,dir,a,x,at);err==nil{t.Fatal("accepted",kind)}
 }
 if _,err:=Authenticate(raw,d,dir,a,v,v.ApprovedUntil);err==nil{t.Fatal("expired approval")}
 d.Reviews[0].Note="changed"
 if _,err:=Authenticate(raw,d,dir,a,v,at);err==nil{t.Fatal("changed dossier")}
}
