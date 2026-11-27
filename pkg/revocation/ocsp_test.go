package revocation

import(
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha1"
 "crypto/sha256"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/asn1"
 "math/big"
 "testing"
 "time"

 "github.com/emmansun/gmsm/smx509"
)
func ocspRaw(t *testing.T,v any)asn1.RawValue{
 t.Helper();b,e:=asn1.Marshal(v);if e!=nil{t.Fatal(e)}
 var r asn1.RawValue;if tail,e:=asn1.Unmarshal(b,&r);e!=nil||len(tail)!=0{t.Fatal(e)};return r
}
func ocspWrap(t *testing.T,class,tag int,children ...asn1.RawValue)asn1.RawValue{
 t.Helper();var b []byte;for _,c:=range children{b=append(b,c.FullBytes...)}
 return ocspRaw(t,asn1.RawValue{Class:class,Tag:tag,IsCompound:true,Bytes:b})
}
func TestOfflineOCSP(t *testing.T){
 at:=time.Date(2026,1,2,0,0,0,0,time.UTC)
 k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 l,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 ca:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic OCSP issuer"},NotBefore:at.AddDate(-1,0,0),NotAfter:at.AddDate(1,0,0),IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature}
 rd,e:=x509.CreateCertificate(rand.Reader,ca,ca,&k.PublicKey,k);if e!=nil{t.Fatal(e)}
 rc,e:=x509.ParseCertificate(rd);if e!=nil{t.Fatal(e)}
 leaf:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic OCSP leaf"},NotBefore:ca.NotBefore,NotAfter:ca.NotAfter,KeyUsage:x509.KeyUsageDigitalSignature}
 ld,e:=x509.CreateCertificate(rand.Reader,leaf,rc,&l.PublicKey,k);if e!=nil{t.Fatal(e)}
 ic,e:=smx509.ParseCertificate(rd);if e!=nil{t.Fatal(e)}
 bits,e:=ocspKeyBits(ic);if e!=nil{t.Fatal(e)}
 build:=func(variant string)[]byte{
  t.Helper()
  raw:=func(v any)asn1.RawValue{return ocspRaw(t,v)}
  seq:=func(v ...asn1.RawValue)asn1.RawValue{return ocspWrap(t,0,16,v...)}
  exp:=func(n int,v asn1.RawValue)asn1.RawValue{return ocspWrap(t,2,n,v)}
  gt:=func(x time.Time)asn1.RawValue{return raw(asn1.RawValue{Tag:24,Bytes:[]byte(x.UTC().Format("20060102150405Z"))})}
  nh:=sha256.Sum256(rc.RawSubject);kh:=sha256.Sum256(bits)
  if variant=="wrong-issuer"{kh[0]^=1}
  serial:=2;if variant=="wrong-serial"{serial=9}
  id:=seq(seq(raw(asn1.ObjectIdentifier{2,16,840,1,101,3,4,2,1})),raw(nh[:]),raw(kh[:]),raw(serial))
  this,produced,next:=at.Add(-time.Hour),at.Add(-time.Minute),at.Add(time.Hour)
  if variant=="stale"{this=at.Add(-3*time.Hour);produced=at.Add(-2*time.Hour);next=at.Add(-time.Hour)}
  if variant=="future"||variant=="later-revoked"{this=at.Add(time.Minute);produced=at.Add(time.Minute);next=at.Add(time.Hour)}
  st:=raw(asn1.RawValue{Class:2,Tag:0})
  if variant=="unknown"{st=raw(asn1.RawValue{Class:2,Tag:2})}
  if variant=="revoked"||variant=="later-revoked"{st=ocspWrap(t,2,1,gt(this.Add(-time.Hour)))}
  responder:=exp(1,asn1.RawValue{FullBytes:rc.RawSubject})
  if variant=="by-key"||variant=="bad-responder"{h:=sha1.Sum(bits);if variant=="bad-responder"{h[0]^=1};responder=exp(2,raw(h[:]))}
  tbs:=seq(responder,gt(produced),seq(seq(id,st,gt(this),exp(0,gt(next)))))
  digest:=sha256.Sum256(tbs.FullBytes)
  sig,e:=ecdsa.SignASN1(rand.Reader,k,digest[:]);if e!=nil{t.Fatal(e)}
  if variant=="bad-signature"{sig[len(sig)-1]^=1}
  basic:=seq(tbs,seq(raw(asn1.ObjectIdentifier{1,2,840,10045,4,3,2})),raw(asn1.BitString{Bytes:sig,BitLength:8*len(sig)}))
  return seq(raw(asn1.Enumerated(0)),exp(0,seq(raw(asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,1,1}),raw(basic.FullBytes)))).FullBytes
 }
 for _,tc:=range []struct{variant,status,candidate string}{
 {"good","NON_REVOKED_INDICATIONS_ONLY","GOOD_IN_AUTHENTICATED_RESPONSE"},
 {"by-key","NON_REVOKED_INDICATIONS_ONLY","GOOD_IN_AUTHENTICATED_RESPONSE"},
 {"revoked","REVOKED_IN_SUPPLIED_EVIDENCE","REVOKED_IN_AUTHENTICATED_RESPONSE"},
 {"unknown","INCOMPLETE_SUPPLIED_EVIDENCE","UNKNOWN_IN_AUTHENTICATED_RESPONSE"},
 {"stale","INCOMPLETE_SUPPLIED_EVIDENCE","OUTSIDE_UPDATE_INTERVAL"},
 {"bad-signature","INCOMPLETE_SUPPLIED_EVIDENCE","REJECTED"},
 {"bad-responder","INCOMPLETE_SUPPLIED_EVIDENCE","REJECTED"},
 {"wrong-issuer","INCOMPLETE_SUPPLIED_EVIDENCE",""},
 {"wrong-serial","INCOMPLETE_SUPPLIED_EVIDENCE",""},
 }{
  der:=build(tc.variant);s,e:=LoadOCSPBytes([][]byte{der});if e!=nil{t.Fatal(tc.variant,e)}
  r,e:=EvaluatePair(ld,rd,nil,s,Options{at,at});if e!=nil||r.Status!=tc.status||r.ReleaseAuthenticated{t.Fatal(tc,r,e)}
  if tc.candidate==""{if len(r.OCSP)!=0{t.Fatal(r)}}else if len(r.OCSP)!=1||r.OCSP[0].Status!=tc.candidate{t.Fatal(tc,r)}
  if _,e:=parseOCSP(append(bytes.Clone(der),0));e==nil{t.Fatal("trailing DER accepted")}
 }
 good,revoked:=build("good"),build("revoked")
 s,e:=LoadOCSPBytes([][]byte{good,revoked});if e!=nil{t.Fatal(e)}
 r,e:=EvaluatePair(ld,rd,nil,s,Options{at,at});if e!=nil||r.Status!="REVOKED_IN_SUPPLIED_EVIDENCE"||!r.Conflict{t.Fatal(r,e)}
 s,e=LoadOCSPBytes([][]byte{build("later-revoked")});if e!=nil{t.Fatal(e)}
 r,e=EvaluatePair(ld,rd,nil,s,Options{at,at.Add(2*time.Hour)});if e!=nil||len(r.HistoricalIndications)!=1||r.Status!="INCOMPLETE_SUPPLIED_EVIDENCE"{t.Fatal(r,e)}
 if _,e:=LoadOCSPBytes([][]byte{good,good});e==nil{t.Fatal("duplicate response accepted")}
}
func FuzzOCSP(f *testing.F){f.Add([]byte{0x30,0});f.Fuzz(func(t *testing.T,b []byte){parseOCSP(b)})}
