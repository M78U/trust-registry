package registry

import(
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/asn1"
 "encoding/pem"
 "math/big"
 "testing"
 "time"
)
func bundleTestCert(t *testing.T,serial int64,ca bool)[]byte{
 t.Helper();k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 v:=&x509.Certificate{SerialNumber:big.NewInt(serial),Subject:pkix.Name{CommonName:"Synthetic CA"},NotBefore:now,NotAfter:now.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:ca,KeyUsage:x509.KeyUsageCertSign}
 b,err:=x509.CreateCertificate(rand.Reader,v,v,&k.PublicKey,k);if err!=nil{t.Fatal(err)};return b
}
func bundlePKCS7(t *testing.T,certs,content,signers []byte)[]byte{
 t.Helper()
 enc:=func(v any)[]byte{b,err:=asn1.Marshal(v);if err!=nil{t.Fatal(err)};return b}
 wrap:=func(class,tag int,b []byte)[]byte{return enc(asn1.RawValue{Class:class,Tag:tag,IsCompound:true,Bytes:b})}
 seq:=func(b []byte)[]byte{return wrap(0,asn1.TagSequence,b)}
 set:=func(b []byte)[]byte{return wrap(0,asn1.TagSet,b)}
 body:=append(enc(1),set(nil)...)
 body=append(body,seq(append(enc(oidData),content...))...)
 body=append(body,wrap(2,0,certs)...)
 body=append(body,set(signers)...)
 return seq(append(enc(oidSignedData),wrap(2,0,seq(body))...))
}
func TestCertificateBundleStrictFormats(t *testing.T){
 a,b:=bundleTestCert(t,1,true),bundleTestCert(t,2,true)
 pe:=func(b []byte)[]byte{return pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:b})}
 bundle:=append(pe(a),pe(b)...)
 pk:=bundlePKCS7(t,append(bytes.Clone(a),b...),nil,nil)
 for _,v:=range []struct{raw []byte;format string;count int}{{a,"SINGLE_DER",1},{bundle,"PEM_CERTIFICATES",2},{pk,"PKCS7_DER_CERTIFICATES_ONLY",2},{pem.EncodeToMemory(&pem.Block{Type:"PKCS7",Bytes:pk}),"PKCS7_PEM_CERTIFICATES_ONLY",2}}{
  f,m,err:=ParseCertificateBundle(v.raw);if err!=nil||f!=v.format||len(m)!=v.count||!bytes.Equal(m[0].DER,a){t.Fatal(f,err)}
 }
 for _,raw:=range [][]byte{
  append(bytes.Clone(a),b...),
  append(pe(a),pe(a)...),
  append(pe(a),pe(bundleTestCert(t,3,false))...),
  append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"),bundle...),
  append(pe(a),[]byte("garbage")...),
  append(pe(a),pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:[]byte{1}})...),
  bundlePKCS7(t,a,[]byte{0xa0,0},nil),
  bundlePKCS7(t,a,nil,[]byte{0x30,0}),
 }{if _,_,err:=ParseCertificateBundle(raw);err==nil{t.Fatal("invalid bundle accepted")}}
 s,err:=OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 now:=time.Date(2026,11,27,0,0,0,0,time.UTC)
 if _,err:=s.ImportBundleCandidates(bundle,"https://example.org/chain",now,[]string{digest(a),digest([]byte("missing"))});err==nil{t.Fatal("unknown selection")}
 before,err:=s.Validate();if err!=nil||before.Certificates!=0{t.Fatal(before,err)}
 first,err:=s.ImportBundleCandidates(bundle,"https://example.org/chain",now,[]string{digest(a)});if err!=nil||len(first)!=1||first[0].Provenance.SourceFileSHA256!=digest(bundle){t.Fatal(first,err)}
 second,err:=s.ImportBundleCandidates(bundle,"https://example.org/chain",now,[]string{digest(a)});if err!=nil||second[0].ProvenanceID!=first[0].ProvenanceID{t.Fatal(second,err)}
 after,err:=s.Validate();if err!=nil||after.Certificates!=1||after.ProvenanceRecords!=1{t.Fatal(after,err)}
}
