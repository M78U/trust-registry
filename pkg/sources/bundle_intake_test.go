package sources

import(
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "math/big"
 "os"
 "path/filepath"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
)
func TestBundlePlanArchiveAndSelection(t *testing.T){
 c,err:=MultiCA();if err!=nil{t.Fatal(err)}
 at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
 makeCert:=func(name string,n int64)[]byte{
  t.Helper();k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
  v:=&x509.Certificate{SerialNumber:big.NewInt(n),Subject:pkix.Name{CommonName:name},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
  der,err:=x509.CreateCertificate(rand.Reader,v,v,&k.PublicKey,k);if err!=nil{t.Fatal(err)};return der
 }
 a,b:=makeCert("CFCA Identity CA",1),makeCert("Unknown synthetic CA",2)
 for i:=range c.Entries{if c.Entries[i].ID=="cfca-identity-ca"{f:=*c.Entries[i].PublishedSHA256;f.Fingerprint=intakeHash(a);c.Entries[i].PublishedSHA256=&f}}
 raw:=append(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:a}),pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:b})...)
 p,m,err:=prepareBundle(c,"cfca-document-chain",raw,at)
 if err!=nil||len(m)!=2||p.Members[0].MatchStatus!="MATCHED_PUBLISHED_LEAD"||p.Members[1].MatchStatus!="UNMATCHED_RESEARCH_CANDIDATE"{t.Fatal(p,err)}
 pb,err:=BundlePlanBytes(p);if err!=nil{t.Fatal(err)}
 pin:=intakeHash(pb)
 dir:=t.TempDir()
 files:=map[string][]byte{"original.bin":raw,"plan.json":pb,intakeHash(a)+".der":a,intakeHash(b)+".der":b}
 for name,data:=range files{if err:=os.WriteFile(filepath.Join(dir,name),data,0600);err!=nil{t.Fatal(err)}}
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 if _,err:=applyBundleArchive(s,c,dir,pin,[]string{intakeHash(b)});err==nil{t.Fatal("unmatched member imported")}
 if err:=os.WriteFile(filepath.Join(dir,intakeHash(b)+".der"),a,0600);err!=nil{t.Fatal(err)}
 if _,err:=applyBundleArchive(s,c,dir,pin,[]string{intakeHash(a)});err==nil{t.Fatal("changed archive accepted")}
 if err:=os.WriteFile(filepath.Join(dir,intakeHash(b)+".der"),b,0600);err!=nil{t.Fatal(err)}
 inspected,records,err:=inspectBundleArchive(c,dir,pin)
 if err!=nil||inspected.OriginalSHA256!=intakeHash(raw)||len(records)!=1||records[0].CertificateSHA256!=intakeHash(a){t.Fatal(inspected,records,err)}
 v,err:=applyBundleArchive(s,c,dir,pin,[]string{intakeHash(a)})
 if err!=nil||len(v.Imports)!=1||v.Imports[0].Provenance.SourceFileSHA256!=intakeHash(raw)||v.TrustStatus!="NOT_ESTABLISHED"||v.ReleaseAuthenticated{t.Fatal(v,err)}
 if records[0].SourceFileSHA256!=v.Imports[0].Provenance.SourceFileSHA256||records[0].SourceURL!=v.Imports[0].Provenance.SourceURL||!records[0].RecordedAt.Equal(v.Imports[0].Provenance.RecordedAt){t.Fatal("inspection and import provenance differ")}
}

func TestDirectObservedCertificateArchive(t *testing.T){
 c,err:=MultiCA();if err!=nil{t.Fatal(err)}
 at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
 id:="gdca-gm-sm2-root"
 makeCert:=func(name string,n int64)[]byte{
  t.Helper()
  key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
  tpl:=&x509.Certificate{SerialNumber:big.NewInt(n),Subject:pkix.Name{CommonName:name},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
  der,e:=x509.CreateCertificate(rand.Reader,tpl,tpl,&key.PublicKey,key);if e!=nil{t.Fatal(e)};return der
 }
 der:=makeCert("GDCA GM SM2 ROOT",1)
 other:=makeCert("GDCA TrustAUTH R5 ROOT",2)
 for i:=range c.Entries{
  e:=&c.Entries[i]
  if e.ID==id||e.ID=="gdca-trustauth-r5-root"{
   v:=*e.PublishedSHA256
   if e.ID==id{v.Fingerprint=intakeHash(der)}else{v.Fingerprint=intakeHash(other)}
   e.PublishedSHA256=&v
  }
 }
 // Synthetic ECDSA CA fixtures test exact identity gates, not actual SM2 CA bytes.
 raw:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
 second:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:other})
 for _,v:=range []struct{id string;raw []byte}{
  {id,other},
  {id,append(append([]byte{},raw...),second...)},
  {id,make([]byte,registry.MaxCertificateInput+1)},
  {"gdca-docsign-sm2-ca",raw},
  {"bjca-global-root-ca1",raw},
  {"cfca-identity-ca",raw},
 }{
  if _,_,err:=prepareBundle(c,v.id,v.raw,at);err==nil{t.Fatal("invalid direct intake accepted",v.id)}
 }
 for _,input:=range [][]byte{der,raw}{
  p,m,err:=prepareBundle(c,id,input,at)
  if err!=nil||len(m)!=1||len(p.Members)!=1||p.Members[0].MatchedListingID!=id||p.Members[0].MatchStatus!="MATCHED_PUBLISHED_LEAD"||p.OriginalSHA256!=intakeHash(input)||p.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(p,err)}
 }
 p,_,err:=prepareBundle(c,id,raw,at);if err!=nil{t.Fatal(err)}
 pb,err:=BundlePlanBytes(p);if err!=nil{t.Fatal(err)}
 pin:=intakeHash(pb)
 dir:=t.TempDir()
 for name,data:=range map[string][]byte{"original.bin":raw,"plan.json":pb,intakeHash(der)+".der":der}{
  if err:=os.WriteFile(filepath.Join(dir,name),data,0600);err!=nil{t.Fatal(err)}
 }
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 if _,err:=applyBundleArchive(s,c,dir,pin,[]string{intakeHash(other)});err==nil{t.Fatal("wrong member imported")}
 if _,err:=applyBundleArchive(s,c,dir,intakeHash([]byte("wrong")),[]string{intakeHash(der)});err==nil{t.Fatal("wrong plan pin accepted")}
 if err:=os.WriteFile(filepath.Join(dir,"original.bin"),der,0600);err!=nil{t.Fatal(err)}
 if _,err:=applyBundleArchive(s,c,dir,pin,[]string{intakeHash(der)});err==nil{t.Fatal("changed original encoding accepted")}
 if err:=os.WriteFile(filepath.Join(dir,"original.bin"),raw,0600);err!=nil{t.Fatal(err)}
 inspected,provenance,err:=inspectBundleArchive(c,dir,pin)
 if err!=nil||inspected.Listing.ID!=id||len(provenance)!=1||provenance[0].SourceFileSHA256!=intakeHash(raw){t.Fatal(inspected,provenance,err)}
 for i:=0;i<2;i++{
  r,err:=applyBundleArchive(s,c,dir,pin,[]string{intakeHash(der)})
  if err!=nil||len(r.Imports)!=1||r.Imports[0].Provenance.SourceFileSHA256!=intakeHash(raw)||r.TrustStatus!="NOT_ESTABLISHED"||r.ReleaseAuthenticated{t.Fatal(r,err)}
 }
 // The matched name is required even with the correct published fingerprint.
 for i:=range c.Entries{if c.Entries[i].ID==id{c.Entries[i].Label="different CN"}}
 if _,_,err:=prepareBundle(c,id,raw,at);err==nil{t.Fatal("wrong subject accepted")}
 if _,_,err:=inspectBundleArchive(c,dir,pin);err==nil{t.Fatal("changed catalog accepted")}
}
