package revocation

import (
 "bytes"
 "crypto/rand"
 "crypto/x509/pkix"
 "encoding/asn1"
 "math/big"
 "testing"
 "time"

 "github.com/emmansun/gmsm/sm2"
 "github.com/emmansun/gmsm/smx509"
)
func TestOfflineCRL(t *testing.T){
 at:=time.Date(2026,1,2,0,0,0,0,time.UTC)
 k,e:=sm2.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 l,e:=sm2.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 root:=&smx509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic CRL issuer"},IsCA:true,BasicConstraintsValid:true,KeyUsage:smx509.KeyUsageCertSign|smx509.KeyUsageCRLSign,SignatureAlgorithm:smx509.SM2WithSM3,NotBefore:at.AddDate(-1,0,0),NotAfter:at.AddDate(1,0,0)}
 rd,e:=smx509.CreateCertificate(rand.Reader,root,root,&k.PublicKey,k);if e!=nil{t.Fatal(e)}
 rc,e:=smx509.ParseCertificate(rd);if e!=nil{t.Fatal(e)}
 leaf:=&smx509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic leaf"},SignatureAlgorithm:smx509.SM2WithSM3,NotBefore:root.NotBefore,NotAfter:root.NotAfter,KeyUsage:smx509.KeyUsageDigitalSignature}
 ld,e:=smx509.CreateCertificate(rand.Reader,leaf,rc,&l.PublicKey,k);if e!=nil{t.Fatal(e)}
 makeList:=func(n int64,revoked,delta bool,from,to time.Time)[]byte{
  t.Helper()
  v:=&smx509.RevocationList{Number:big.NewInt(n),ThisUpdate:from,NextUpdate:to,SignatureAlgorithm:smx509.SM2WithSM3}
  if revoked{v.RevokedCertificateEntries=[]smx509.RevocationListEntry{{SerialNumber:big.NewInt(2),RevocationTime:from.Add(-time.Hour),ReasonCode:1}}}
  if delta{b,_:=asn1.Marshal(1);v.ExtraExtensions=[]pkix.Extension{{Id:asn1.ObjectIdentifier{2,5,29,27},Critical:true,Value:b}}}
  d,e:=smx509.CreateRevocationList(rand.Reader,v,rc,k);if e!=nil{t.Fatal(e)}
  return d
 }
 clean:=makeList(1,false,false,at.Add(-time.Hour),at.Add(time.Hour))
 revoked:=makeList(2,true,false,at.Add(-time.Hour),at.Add(time.Hour))
 later:=makeList(7,true,false,at.Add(time.Hour),at.Add(2*time.Hour))
 stale:=makeList(3,false,false,at.Add(-3*time.Hour),at.Add(-time.Hour))
 delta:=makeList(4,false,true,at.Add(-time.Hour),at.Add(time.Hour))
 damaged:=bytes.Clone(clean);damaged[len(damaged)-1]^=1
 for _,tc:=range []struct{raw []byte;status,candidate string}{
 {clean,"NON_REVOKED_INDICATIONS_ONLY","SERIAL_NOT_LISTED"},
 {revoked,"REVOKED_IN_SUPPLIED_EVIDENCE","REVOKED_AT_EVALUATION_TIME"},
 {stale,"INCOMPLETE_SUPPLIED_EVIDENCE","OUTSIDE_UPDATE_INTERVAL"},
 {delta,"INCOMPLETE_SUPPLIED_EVIDENCE","REJECTED"},
 {damaged,"INCOMPLETE_SUPPLIED_EVIDENCE","REJECTED"},
 }{
  s,e:=LoadCRLBytes(tc.raw);if e!=nil{t.Fatal(e)}
  r,e:=EvaluatePair(ld,rd,s,nil,Options{at,at});if e!=nil||r.Status!=tc.status||len(r.CRLs)!=1||r.CRLs[0].Status!=tc.candidate||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(r,e)}
 }
 s,e:=LoadCRLBytes(later);if e!=nil{t.Fatal(e)}
 r,e:=EvaluatePair(ld,rd,s,nil,Options{at,at});if e!=nil||len(r.CRLs)!=0||len(r.HistoricalIndications)!=0{t.Fatal(r,e)}
 r,e=EvaluatePair(ld,rd,s,nil,Options{at,at.Add(3*time.Hour)});if e!=nil||r.Status!="INCOMPLETE_SUPPLIED_EVIDENCE"||len(r.HistoricalIndications)!=1||r.HistoricalIndications[0].TemporalStatus!="ISSUED_AFTER_EVALUATION_TIME"{t.Fatal(r,e)}
 if _,e:=EvaluatePair(ld,ld,s,nil,Options{at,at});e==nil{t.Fatal("invalid issuer accepted")}
 if _,e:=LoadCRLBytes(append(bytes.Clone(clean),0));e==nil{t.Fatal("trailing DER")}
}
