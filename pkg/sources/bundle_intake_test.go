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
