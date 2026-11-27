package snapshot

import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/json"
 "math/big"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
)
func TestConsumerCandidateExport(t *testing.T){
 at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 key:=func()*ecdsa.PrivateKey{k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)};return k}
 ca:=func(n int64,name string)*x509.Certificate{return &x509.Certificate{SerialNumber:big.NewInt(n),Subject:pkix.Name{CommonName:name},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}}
 mk:=func(c,p *x509.Certificate,k,sk *ecdsa.PrivateKey)([]byte,*x509.Certificate){raw,e:=x509.CreateCertificate(rand.Reader,c,p,&k.PublicKey,sk);if e!=nil{t.Fatal(e)};v,e:=x509.ParseCertificate(raw);if e!=nil{t.Fatal(e)};return raw,v}
 rk,ik,wk,lk:=key(),key(),key(),key()
 rt:=ca(1,"Root");root,pr:=mk(rt,rt,rk,rk)
 inter,pi:=mk(ca(2,"Intermediate"),pr,ik,rk)
 wrong,_:=mk(ca(3,"Intermediate"),pr,wk,rk)
 lt:=ca(4,"Signer");lt.IsCA=false;lt.KeyUsage=x509.KeyUsageDigitalSignature
 leaf,_:=mk(lt,pi,lk,ik)
 s,e:=registry.OpenStore(t.TempDir());if e!=nil{t.Fatal(e)}
 for _,v:=range [][]byte{root,inter,wrong}{if _,e:=s.Import(v,"https://example.org/ca",at);e!=nil{t.Fatal(e)}}
 raw,report,e:=Build(s,nil,Options{Sequence:1,SourceRevision:strings.Repeat("a",40),CreatedAt:at,ExpiresAt:at.Add(time.Hour)});if e!=nil{t.Fatal(e)}
 v,_,e:=LoadPinnedResearch(raw,report.SnapshotSHA256,at);if e!=nil{t.Fatal(e)}
 got,e:=v.CandidateBundle(leaf);if e!=nil{t.Fatal(e)}
 var b ConsumerBundle
 if e:=json.Unmarshal(got,&b);e!=nil{t.Fatal(e)}
 if len(b.Certificates)!=1||b.Certificates[0].SHA256!=digest(inter)||len(b.Certificates[0].ProvenanceIDs)!=1||b.SnapshotSHA256!=report.SnapshotSHA256{t.Fatalf("unexpected candidates: %+v",b)}
 all,e:=v.CandidateBundle(nil);if e!=nil{t.Fatal(e)}
 if e:=json.Unmarshal(all,&b);e!=nil||len(b.Certificates)!=2{t.Fatalf("all candidates: %+v %v",b,e)}
}
