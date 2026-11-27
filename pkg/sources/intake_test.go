package sources

import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha1"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/hex"
 "encoding/pem"
 "math/big"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
)

func TestOfflineIntakePlanAndApply(t *testing.T){
 at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
 c,err:=SHECA();if err!=nil{t.Fatal(err)}
 endpoints,err:=Endpoints();if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 chosen:=[]Endpoint{endpoints[0],endpoints[1]}
 for i:=range chosen{
  k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
  tmpl:=&x509.Certificate{SerialNumber:big.NewInt(int64(i+1)),Subject:pkix.Name{CommonName:"Synthetic batch CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
  der,err:=x509.CreateCertificate(rand.Reader,tmpl,tmpl,&k.PublicKey,k);if err!=nil{t.Fatal(err)}
  h:=sha1.Sum(der)
  for j:=range c.Entries{if c.Entries[j].ID==chosen[i].ListingID{c.Entries[j].PublishedSHA1=hex.EncodeToString(h[:])}}
  chosen[i].PublishedSHA256=&FingerprintEvidence{intakeHash(der),"https://example.org/fixture","SYNTHETIC"}
  if err:=os.WriteFile(filepath.Join(dir,chosen[i].ListingID+".cer"),der,0600);err!=nil{t.Fatal(err)}
 }
 ids:=[]string{chosen[1].ListingID,chosen[0].ListingID}
 plan,err:=prepareIntake(c,chosen,dir,ids,at,false);if err!=nil{t.Fatal(err)}
 raw,err:=IntakePlanBytes(plan.plan);if err!=nil{t.Fatal(err)}
 pin:=intakeHash(raw)
 again,err:=prepareIntake(c,chosen,dir,[]string{ids[1],ids[0]},at,false);if err!=nil{t.Fatal(err)}
 b,err:=IntakePlanBytes(again.plan);if err!=nil||intakeHash(b)!=pin{t.Fatal("unstable plan",err)}
 if _,err:=prepareIntake(c,chosen,dir,[]string{ids[0],ids[0]},at,false);err==nil{t.Fatal("duplicate ID accepted")}
 if _,err:=prepareIntake(c,chosen,dir,[]string{"../escape"},at,false);err==nil{t.Fatal("path traversal accepted")}
 if _,err:=DecodeIntakePlan(raw,strings.Repeat("a",64));err==nil{t.Fatal("wrong plan pin")}
 store,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=store.Init();err!=nil{t.Fatal(err)}
 // Same DER in a different input encoding must invalidate the pinned
 // observation; all preflight checks complete before importing anything.
 name:=filepath.Join(dir,plan.plan.Items[1].FileName)
 original,err:=os.ReadFile(name);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(name,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:original}),0600);err!=nil{t.Fatal(err)}
 if _,err:=applyIntake(store,c,chosen,dir,raw,pin);err==nil{t.Fatal("changed input accepted")}
 before,err:=store.Validate();if err!=nil||before.Certificates!=0||before.ProvenanceRecords!=0{t.Fatal(before,err)}
 if err:=os.WriteFile(name,original,0600);err!=nil{t.Fatal(err)}
 altered:=append([]Endpoint{},chosen...)
 altered[0].ObservedOn="2026-11-26"
 if _,err:=applyIntake(store,c,altered,dir,raw,pin);err==nil{t.Fatal("changed endpoint catalog accepted")}
 result,err:=applyIntake(store,c,chosen,dir,raw,pin)
 if err!=nil||result.Status!="UNREVIEWED_BATCH_IMPORTED"||result.After.Certificates!=2||result.After.ProvenanceRecords!=2||result.ReleaseAuthenticated||result.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(result,err)}
 for _,v:=range result.Imports{if v.Provenance.ReviewStatus!="CANDIDATE"||v.Provenance.RedistributionStatus!="NOT_REVIEWED"||!v.Provenance.RecordedAt.Equal(at){t.Fatal(v)}}
 retry,err:=applyIntake(store,c,chosen,dir,raw,pin);if err!=nil||retry.After!=result.After||retry.Imports[0].ProvenanceID!=result.Imports[0].ProvenanceID{t.Fatal(retry,err)}
 altered[0]=chosen[0];altered[0].PublishedSHA256=nil
 if _,err:=prepareIntake(c,altered,dir,ids,at,false);err==nil{t.Fatal("legacy-only accepted")}
 if v,err:=prepareIntake(c,altered,dir,ids,at,true);err!=nil||!v.plan.AllowLegacyOnly{t.Fatal(v,err)}
}
