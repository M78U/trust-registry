package revocation

import (
 "bytes"
 "crypto"
 "crypto/sha1"
 _ "crypto/sha512"
 "encoding/asn1"
 "errors"
 "math/big"
 "sort"
 "time"

 "github.com/emmansun/gmsm/smx509"
)

// Only direct issuer BasicOCSPResponse, single CertID, no extensions.
// SHA-1 is permitted for protocol identifiers, never response signatures.
type ocspResponse struct{
 raw,tbs,signature,embedded,issuerNameHash,issuerKeyHash []byte
 responder asn1.RawValue
 hash crypto.Hash
 algorithm smx509.SignatureAlgorithm
 serial *big.Int
 status string
 produced,this,next time.Time
 revoked *time.Time
}
type OCSPStore struct{responses []*ocspResponse; fingerprints []string}
type OCSPCandidate struct{
 AuthenticatedAssertion string `json:"authenticatedAssertion,omitempty"`
 ResponseSHA256 string `json:"responseSHA256"`
 Status string `json:"status"`
 Reason string `json:"reason,omitempty"`
 ProducedAt time.Time `json:"producedAt"`
 ThisUpdate time.Time `json:"thisUpdate"`
 NextUpdate time.Time `json:"nextUpdate"`
 RevocationTime *time.Time `json:"revocationTime,omitempty"`
}
func(s *OCSPStore) Fingerprints()[]string{if s==nil{return nil};return append([]string(nil),s.fingerprints...)}
func ocspTag(v asn1.RawValue,class,tag int,compound bool)bool{return v.Class==class&&v.Tag==tag&&v.IsCompound==compound}
func ocspFields(v asn1.RawValue,n int)([]asn1.RawValue,error){
 if !ocspTag(v,0,16,true){return nil,errors.New("expected OCSP sequence")}
 return ocspChildren(v,n)
}
func ocspChildren(v asn1.RawValue,n int)([]asn1.RawValue,error){
 b:=v.Bytes;out:=[]asn1.RawValue{}
 for len(b)>0{
  if len(out)>=n{return nil,errors.New("unsupported OCSP field count")}
  var x asn1.RawValue;var e error
  b,e=asn1.Unmarshal(b,&x);if e!=nil{return nil,e};out=append(out,x)
 }
 return out,nil
}
func ocspExact(v asn1.RawValue,n int)([]asn1.RawValue,error){
 a,e:=ocspFields(v,n);if e!=nil{return nil,e};if len(a)!=n{return nil,errors.New("missing OCSP fields")};return a,nil
}
func ocspDecode(v asn1.RawValue,out any)error{b,e:=asn1.Unmarshal(v.FullBytes,out);if e!=nil{return e};if len(b)!=0{return errors.New("trailing ASN.1 data")};return nil}
func ocspExplicit(v asn1.RawValue,tag int)(asn1.RawValue,error){
 if !ocspTag(v,2,tag,true){return asn1.RawValue{},errors.New("invalid explicit OCSP tag")}
 a,e:=ocspChildren(v,1);if e!=nil||len(a)!=1{return asn1.RawValue{},errors.New("invalid explicit OCSP contents")};return a[0],nil
}
func ocspAlgorithm(v asn1.RawValue)(string,bool,error){
 a,e:=ocspFields(v,2);if e!=nil||len(a)==0{return "",false,errors.New("invalid OCSP algorithm")}
 var oid asn1.ObjectIdentifier;if e=ocspDecode(a[0],&oid);e!=nil{return "",false,e}
 null:=len(a)==2
 if null&&(!ocspTag(a[1],0,5,false)||len(a[1].Bytes)!=0){return "",false,errors.New("unsupported OCSP algorithm parameters")}
 return oid.String(),null,nil
}
func ocspHash(v asn1.RawValue)(crypto.Hash,error){
 oid,_,e:=ocspAlgorithm(v);if e!=nil{return 0,e}
 switch oid{case "1.3.14.3.2.26":return crypto.SHA1,nil;case "2.16.840.1.101.3.4.2.1":return crypto.SHA256,nil;case "2.16.840.1.101.3.4.2.2":return crypto.SHA384,nil;case "2.16.840.1.101.3.4.2.3":return crypto.SHA512,nil}
 return 0,errors.New("unsupported OCSP CertID hash")
}
func ocspSignature(v asn1.RawValue)(smx509.SignatureAlgorithm,error){
 oid,null,e:=ocspAlgorithm(v);if e!=nil{return 0,e}
 switch oid{
 case "1.2.840.113549.1.1.11":return smx509.SHA256WithRSA,nil
 case "1.2.840.113549.1.1.12":return smx509.SHA384WithRSA,nil
 case "1.2.840.113549.1.1.13":return smx509.SHA512WithRSA,nil
 case "1.2.840.10045.4.3.2":if !null{return smx509.ECDSAWithSHA256,nil}
 case "1.2.840.10045.4.3.3":if !null{return smx509.ECDSAWithSHA384,nil}
 case "1.2.840.10045.4.3.4":if !null{return smx509.ECDSAWithSHA512,nil}
 case "1.2.156.10197.1.501":if !null{return smx509.SM2WithSM3,nil}
 }
 return 0,errors.New("unsupported OCSP response signature algorithm")
}
func ocspTime(v asn1.RawValue)(time.Time,error){
 var t time.Time
 if !ocspTag(v,0,24,false)||ocspDecode(v,&t)!=nil||t.IsZero(){return t,errors.New("invalid OCSP GeneralizedTime")}
 return t.UTC(),nil
}
func parseOCSP(der []byte)(*ocspResponse,error){
 if len(der)==0||len(der)>1<<20{return nil,errors.New("OCSP response size limit")}
 var root asn1.RawValue
 tail,e:=asn1.Unmarshal(der,&root);if e!=nil||len(tail)!=0{return nil,errors.New("invalid OCSP DER")}
 a,e:=ocspExact(root,2);if e!=nil{return nil,e}
 var status asn1.Enumerated
 if ocspDecode(a[0],&status)!=nil||status!=0{return nil,errors.New("successful OCSP response required")}
 rb,e:=ocspExplicit(a[1],0);if e!=nil{return nil,e}
 b,e:=ocspExact(rb,2);if e!=nil{return nil,e}
 var oid asn1.ObjectIdentifier
 if ocspDecode(b[0],&oid)!=nil||oid.String()!="1.3.6.1.5.5.7.48.1.1"||!ocspTag(b[1],0,4,false){return nil,errors.New("BasicOCSPResponse required")}
 var basic asn1.RawValue
 tail,e=asn1.Unmarshal(b[1].Bytes,&basic);if e!=nil||len(tail)!=0{return nil,errors.New("invalid basic OCSP DER")}
 f,e:=ocspFields(basic,4);if e!=nil||len(f)<3{return nil,errors.New("invalid basic OCSP fields")}
 r:=&ocspResponse{raw:bytes.Clone(der),tbs:f[0].FullBytes}
 r.algorithm,e=ocspSignature(f[1]);if e!=nil{return nil,e}
 var sig asn1.BitString
 if ocspDecode(f[2],&sig)!=nil||len(sig.Bytes)==0||len(sig.Bytes)>1024||sig.BitLength!=8*len(sig.Bytes){return nil,errors.New("invalid OCSP signature")}
 r.signature=sig.Bytes
 if len(f)==4{
  v,e:=ocspExplicit(f[3],0);if e!=nil{return nil,e}
  cs,e:=ocspExact(v,1);if e!=nil||!ocspTag(cs[0],0,16,true){return nil,errors.New("only one optional embedded issuer certificate supported")}
  r.embedded=cs[0].FullBytes
 }
 d,e:=ocspExact(f[0],3);if e!=nil{return nil,e}
 if d[0].Class!=2||(d[0].Tag!=1&&d[0].Tag!=2){return nil,errors.New("unsupported ResponderID")}
 r.responder,e=ocspExplicit(d[0],d[0].Tag);if e!=nil{return nil,e}
 if d[0].Tag==1&&!ocspTag(r.responder,0,16,true)||d[0].Tag==2&&(!ocspTag(r.responder,0,4,false)||len(r.responder.Bytes)!=20){return nil,errors.New("invalid ResponderID")}
 r.produced,e=ocspTime(d[1]);if e!=nil{return nil,e}
 sr,e:=ocspExact(d[2],1);if e!=nil{return nil,e}
 s,e:=ocspExact(sr[0],4);if e!=nil{return nil,e}
 id,e:=ocspExact(s[0],4);if e!=nil{return nil,e}
 r.hash,e=ocspHash(id[0]);if e!=nil{return nil,e}
 for _,v:=range id[1:3]{if !ocspTag(v,0,4,false)||len(v.Bytes)!=r.hash.Size(){return nil,errors.New("invalid CertID hash length")}}
 r.issuerNameHash=id[1].Bytes;r.issuerKeyHash=id[2].Bytes
 if ocspDecode(id[3],&r.serial)!=nil||r.serial==nil||r.serial.Sign()<=0||r.serial.BitLen()>160{return nil,errors.New("invalid CertID serial")}
 switch{
 case ocspTag(s[1],2,0,false)&&len(s[1].Bytes)==0:r.status="GOOD"
 case ocspTag(s[1],2,2,false)&&len(s[1].Bytes)==0:r.status="UNKNOWN"
 case ocspTag(s[1],2,1,true):
  v,e:=ocspChildren(s[1],2);if e!=nil||len(v)==0{return nil,errors.New("invalid revoked info")}
  t,e:=ocspTime(v[0]);if e!=nil{return nil,e};r.revoked=&t;r.status="REVOKED"
  if len(v)==2{
   x,e:=ocspExplicit(v[1],0);if e!=nil{return nil,e};var reason asn1.Enumerated
   if ocspDecode(x,&reason)!=nil{return nil,errors.New("invalid OCSP reason")}
   switch reason{case 0,1,2,3,4,5,6,9,10:default:return nil,errors.New("unsupported OCSP reason")}
  }
 default:return nil,errors.New("unsupported OCSP certStatus")
 }
 r.this,e=ocspTime(s[2]);if e!=nil{return nil,e}
 nx,e:=ocspExplicit(s[3],0);if e!=nil{return nil,e}
 r.next,e=ocspTime(nx);if e!=nil{return nil,e}
 if r.produced.Before(r.this)||!r.next.After(r.produced)||(r.revoked!=nil&&r.revoked.After(r.this)){return nil,errors.New("invalid OCSP chronology")}
 return r,nil
}
// Explicit DER files, no PEM or automatic network discovery. Aggregate limits
// are applied before parsing the response set.
func LoadOCSPBytes(inputs [][]byte)(*OCSPStore,error){
 if len(inputs)==0||len(inputs)>16{return nil,errors.New("OCSP input count limit")}
 return loadOCSP(len(inputs),func(i int)([]byte,error){return inputs[i],nil})
}
func loadOCSP(n int,read func(int)([]byte,error))(*OCSPStore,error){
 s:=&OCSPStore{};seen:=map[string]bool{};total:=0
 for i:=0;i<n;i++{
  b,e:=read(i);if e!=nil{return nil,e}
  if len(b)==0||len(b)>1<<20||len(b)>maxBundle-total{return nil,errors.New("OCSP member or total size limit")}
  total+=len(b);b=bytes.Clone(b)
  r,e:=parseOCSP(b);if e!=nil{return nil,e}
  fp:=fingerprint(b);if seen[fp]{return nil,errors.New("duplicate OCSP response")};seen[fp]=true
  s.responses=append(s.responses,r);s.fingerprints=append(s.fingerprints,fp)
 }
 sort.Strings(s.fingerprints);sort.Slice(s.responses,func(i,j int)bool{return fingerprint(s.responses[i].raw)<fingerprint(s.responses[j].raw)})
 return s,nil
}
func ocspKeyBits(c *smx509.Certificate)([]byte,error){
 var spki struct{Algorithm asn1.RawValue;Key asn1.BitString}
 b,e:=asn1.Unmarshal(c.RawSubjectPublicKeyInfo,&spki);if e!=nil||len(b)!=0||spki.Key.BitLength==0{return nil,errors.New("invalid issuer SPKI")}
 return spki.Key.RightAlign(),nil
}
func ocspDigest(h crypto.Hash,b []byte)[]byte{d:=h.New();d.Write(b);return d.Sum(nil)}
func(r *ocspResponse) inspect(cert,issuer *smx509.Certificate,at time.Time)(OCSPCandidate,bool){
 v:=OCSPCandidate{ResponseSHA256:fingerprint(r.raw),Status:"REJECTED",ProducedAt:r.produced,ThisUpdate:r.this,NextUpdate:r.next}
 if r.serial.Cmp(cert.SerialNumber)!=0{return v,false}
 key,e:=ocspKeyBits(issuer);if e!=nil{return v,false}
 if !bytes.Equal(cert.RawIssuer,issuer.RawSubject)||!bytes.Equal(r.issuerNameHash,ocspDigest(r.hash,cert.RawIssuer))||!bytes.Equal(r.issuerKeyHash,ocspDigest(r.hash,key)){return v,false}
 if len(r.embedded)!=0&&!bytes.Equal(r.embedded,issuer.Raw){v.Reason="delegated responder unsupported";return v,true}
 if ocspTag(r.responder,0,16,true){if !bytes.Equal(r.responder.FullBytes,issuer.RawSubject){v.Reason="ResponderID name mismatch";return v,true}}else{
  h:=sha1.Sum(key);if !bytes.Equal(r.responder.Bytes,h[:]){v.Reason="ResponderID key mismatch";return v,true}
 }
 if !issuer.IsCA||!issuer.BasicConstraintsValid||issuer.KeyUsage!=0&&issuer.KeyUsage&smx509.KeyUsageDigitalSignature==0{v.Reason="issuer signing usage not permitted";return v,true}
 if r.produced.Before(issuer.NotBefore)||r.produced.After(issuer.NotAfter){v.Reason="responder certificate invalid at producedAt";return v,true}
 if e:=issuer.CheckSignature(r.algorithm,r.tbs,r.signature);e!=nil{v.Reason="OCSP response signature invalid";return v,true}
 v.AuthenticatedAssertion=r.status;v.RevocationTime=r.revoked
 if at.Before(r.produced)||at.Before(r.this)||!at.Before(r.next){v.Status="OUTSIDE_UPDATE_INTERVAL";return v,true}
 v.Status=r.status+"_IN_AUTHENTICATED_RESPONSE";v.RevocationTime=r.revoked;return v,true
}
