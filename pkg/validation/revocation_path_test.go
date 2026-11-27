package validation

import (
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

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/revocation"
)

func TestStoredRevocationAcrossPath(t *testing.T){
 at:=time.Date(2026,1,2,0,0,0,0,time.UTC)
 key:=func()*ecdsa.PrivateKey{k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)};return k}
 cert:=func(n int64,name string,ca bool)*x509.Certificate{
  c:=&x509.Certificate{SerialNumber:big.NewInt(n),Subject:pkix.Name{CommonName:name},NotBefore:at.AddDate(-1,0,0),NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:ca,KeyUsage:x509.KeyUsageDigitalSignature}
  if ca{c.KeyUsage|=x509.KeyUsageCertSign|x509.KeyUsageCRLSign};return c
 }
 issue:=func(c,parent *x509.Certificate,k,signer *ecdsa.PrivateKey)([]byte,*x509.Certificate){
  t.Helper();if parent==nil{parent=c};raw,e:=x509.CreateCertificate(rand.Reader,c,parent,&k.PublicKey,signer);if e!=nil{t.Fatal(e)}
  parsed,e:=x509.ParseCertificate(raw);if e!=nil{t.Fatal(e)};return raw,parsed
 }
 rk,ik,lk:=key(),key(),key()
 root,rc:=issue(cert(1,"Synthetic root",true),nil,rk,rk)
 inter,ic:=issue(cert(2,"Synthetic intermediate",true),rc,ik,rk)
 leaf,_:=issue(cert(3,"Synthetic signer",false),ic,lk,ik)
 s,e:=registry.OpenStore(t.TempDir());if e!=nil{t.Fatal(e)}
 a,e:=s.Import(root,"https://example.org/root",at.Add(-time.Hour));if e!=nil{t.Fatal(e)}
 m,e:=s.Import(inter,"https://example.org/inter",at.Add(-time.Hour));if e!=nil{t.Fatal(e)}
 fp:=a.Certificate.FingerprintSHA256
 d:=policy.Document{Policy:policy.Defaults()[0],Reviews:[]policy.Review{{ID:"review",ProvenanceID:a.ProvenanceID,CertificateSHA256:fp,Status:"PROVENANCE_VERIFIED",RecordedAt:at.Add(-time.Hour),Evidence:[]string{"synthetic"},ReviewReferences:[]string{"synthetic"}}},Decisions:[]policy.Decision{}}
 d.Policy.TrustAnchors=[]string{fp};d.Policy.IntermediateCandidates=[]string{m.Certificate.FingerprintSHA256}
 d.Decisions=append(d.Decisions,policy.Decision{ID:"decision",CertificateSHA256:fp,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:policy.Trusted,RecordedAt:at.Add(-time.Hour),EffectiveFrom:at.Add(-time.Hour),Reason:"synthetic approval",EvidenceIDs:[]string{"review"},ReviewReferences:[]string{"synthetic"}})
 makeCRL:=func(issuer *x509.Certificate,k *ecdsa.PrivateKey,revoked bool)[]byte{
  t.Helper();v:=&x509.RevocationList{Number:big.NewInt(1),ThisUpdate:at.Add(-time.Minute),NextUpdate:at.Add(time.Hour)}
  if revoked{v.RevokedCertificateEntries=[]x509.RevocationListEntry{{SerialNumber:big.NewInt(2),RevocationTime:at.Add(-time.Hour),ReasonCode:1}}}
  raw,e:=x509.CreateRevocationList(rand.Reader,v,issuer,k);if e!=nil{t.Fatal(e)};return raw
 }
 dir:=filepath.Join(t.TempDir(),"private")
 store,e:=revocation.OpenEvidenceStore(dir);if e!=nil{t.Fatal(e)}
 if e:=store.Init();e!=nil{t.Fatal(e)}
 if e:=store.Init();e==nil{t.Fatal("implicit reset")}
 verify:=func(known time.Time,want string)LocalPathWithRevocationReport{
  t.Helper();v,e:=VerifyLocalPathWithRevocation(s,d,leaf,d.Policy.Purpose,"",at,known,store)
  if e!=nil||v.Path.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"||v.Revocation.Status!=want||v.Path.RevocationStatus!=want||v.TrustStatus!=policy.Unknown||v.Path.ReleaseAuthenticated||len(v.Revocation.Chains)!=1||len(v.Revocation.Pairs)!=2{t.Fatalf("path %+v %v",v,e)};return v
 }
 verify(at,"INCOMPLETE_SUPPLIED_EVIDENCE")
 clean:=makeCRL(ic,ik,false)
 row,e:=store.Import("CRL",clean,at,"fixture");if e!=nil||row.AlreadyPresent{t.Fatal(row,e)}
 duplicate,e:=store.Import("CRL",pem.EncodeToMemory(&pem.Block{Type:"X509 CRL",Bytes:clean}),at.Add(time.Minute),"later");if e!=nil||!duplicate.AlreadyPresent||duplicate.Record!=row.Record{t.Fatal(duplicate,e)}
 verify(at,"INCOMPLETE_SUPPLIED_EVIDENCE")
 revoked,e:=store.Import("CRL",makeCRL(rc,rk,true),at.Add(time.Minute),"fixture");if e!=nil{t.Fatal(e)}
 before:=verify(at,"INCOMPLETE_SUPPLIED_EVIDENCE");if len(before.Revocation.Observations)!=1{t.Fatal("future observation visible")}
 after:=verify(at.Add(time.Minute),"REVOKED_IN_SUPPLIED_EVIDENCE")
 if len(after.Revocation.Observations)!=2||after.Revocation.Pairs[0].Status!="NON_REVOKED_INDICATIONS_ONLY"||after.Revocation.Pairs[1].Status!="REVOKED_IN_SUPPLIED_EVIDENCE"||after.Revocation.Pairs[1].IssuerSHA256!=fp{t.Fatal(after)}
 if e:=os.WriteFile(filepath.Join(dir,revoked.Record.SHA256+".json"),[]byte("{}"),0600);e!=nil{t.Fatal(e)}
 if _,e:=store.Load(at);e==nil{t.Fatal("corrupt future record ignored")}
}
