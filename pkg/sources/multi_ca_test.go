package sources

import(
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "math/big"
 "testing"
 "time"
)
func TestMultiCACatalog(t *testing.T){
 c,err:=MultiCA();if err!=nil{t.Fatal(err)}
 if len(c.Entries)!=15{t.Fatal(len(c.Entries))}
 count:=0;for _,e:=range c.Entries{if e.PublishedSHA256!=nil{count++}}
 if count!=5{t.Fatal(count)}
 gd,err:=c.Filter("GDCA");if err!=nil||len(gd.Entries)!=5{t.Fatal(gd,err)}
 if _,err:=c.Filter("unknown");err==nil{t.Fatal("unknown authority")}
 for _,id:=range []string{"cfca-document-chain","gdca-docsign-sm2-ca","gdca-trustauth-e1-ca","missing"}{
  if _,err:=AuditMultiCA(id,[]byte("invalid"));err==nil{t.Fatal("unverified lead accepted",id)}
 }
}
func TestMultiCAExactFingerprintAudit(t *testing.T){
 c,err:=MultiCA();if err!=nil{t.Fatal(err)}
 id:="cfca-identity-ca"
 at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 tmpl:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"CFCA Identity CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 der,err:=x509.CreateCertificate(rand.Reader,tmpl,tmpl,&k.PublicKey,k);if err!=nil{t.Fatal(err)}
 if _,err:=auditMultiCA(c,id,der);err==nil{t.Fatal("wrong published digest accepted")}
 for i:=range c.Entries{if c.Entries[i].ID==id{v:=*c.Entries[i].PublishedSHA256;v.Fingerprint=intakeHash(der);c.Entries[i].PublishedSHA256=&v}}
 raw:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
 r,err:=auditMultiCA(c,id,raw)
 if err!=nil||r.FingerprintStatus!="MATCHED_PUBLISHED_LEAD"||r.Certificate.FingerprintSHA256!=intakeHash(der)||r.OriginalSHA256!=intakeHash(raw)||r.RegistryImported||r.ReleaseAuthenticated||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(r,err)}
 for i:=range c.Entries{if c.Entries[i].ID==id{c.Entries[i].Label="different name"}}
 if _,err:=auditMultiCA(c,id,raw);err==nil{t.Fatal("CN mismatch")}
 c.Entries[0].RedistributionStatus="APPROVED"
 if err:=c.Validate();err==nil{t.Fatal("automatic approval")}
}
