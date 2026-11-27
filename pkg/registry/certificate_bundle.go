package registry

import (
 "bytes"
 "encoding/asn1"
 "encoding/pem"
 "errors"
 "fmt"
 "time"
)

const MaxCertificateBundleBytes=16<<20
const MaxCertificateBundleMembers=32

type BundleCertificate struct {
 Certificate CertificateRecord
 DER []byte
}

var oidSignedData=asn1.ObjectIdentifier{1,2,840,113549,1,7,2}
var oidData=asn1.ObjectIdentifier{1,2,840,113549,1,7,1}

func takeASN1(raw []byte,class,tag int,compound bool)(asn1.RawValue,[]byte,error){
 var v asn1.RawValue
 rest,err:=asn1.Unmarshal(raw,&v)
 if err!=nil||v.Class!=class||v.Tag!=tag||v.IsCompound!=compound{return asn1.RawValue{},nil,errors.New("unexpected DER field in certificate container")}
 return v,rest,nil
}

// Certificate-only degenerate PKCS#7 SignedData. No content, digests,
// revocation objects, signers or alternate certificate choices are accepted.
// No signature of the container itself is claimed.
func certificateOnlyPKCS7(raw []byte)([][]byte,error){
 outer,rest,err:=takeASN1(raw,0,asn1.TagSequence,true)
 if err!=nil||len(rest)!=0{return nil,errors.New("invalid PKCS#7 content info")}
 var oid asn1.ObjectIdentifier
 rem,err:=asn1.Unmarshal(outer.Bytes,&oid)
 if err!=nil||!oid.Equal(oidSignedData){return nil,errors.New("expected PKCS#7 SignedData")}
 explicit,rest,err:=takeASN1(rem,2,0,true)
 if err!=nil||len(rest)!=0{return nil,errors.New("invalid SignedData wrapper")}
 signed,rest,err:=takeASN1(explicit.Bytes,0,asn1.TagSequence,true)
 if err!=nil||len(rest)!=0{return nil,errors.New("invalid SignedData")}
 var version int
 rem,err=asn1.Unmarshal(signed.Bytes,&version)
 if err!=nil||version!=1{return nil,errors.New("only SignedData version 1 supported")}
 digestSet,rem,err:=takeASN1(rem,0,asn1.TagSet,true)
 if err!=nil||len(digestSet.Bytes)!=0{return nil,errors.New("certificate-only SignedData must have empty digest set")}
 content,rem,err:=takeASN1(rem,0,asn1.TagSequence,true)
 if err!=nil{return nil,err}
 rest,err=asn1.Unmarshal(content.Bytes,&oid)
 if err!=nil||len(rest)!=0||!oid.Equal(oidData){return nil,errors.New("encapsulated content is not permitted")}
 certSet,rem,err:=takeASN1(rem,2,0,true)
 if err!=nil||len(certSet.Bytes)==0{return nil,errors.New("certificate set required")}
 signers,rest,err:=takeASN1(rem,0,asn1.TagSet,true)
 if err!=nil||len(signers.Bytes)!=0||len(rest)!=0{return nil,errors.New("CRLs, signer infos or trailing fields not permitted")}
 members:=[][]byte{}
 for rem=certSet.Bytes;len(rem)>0;{
  if len(members)>=MaxCertificateBundleMembers{return nil,errors.New("bundle member limit")}
  cert,next,err:=takeASN1(rem,0,asn1.TagSequence,true);if err!=nil{return nil,err}
  if len(cert.FullBytes)>MaxCertificateInput{return nil,errors.New("certificate member size limit")}
  members=append(members,cert.FullBytes);rem=next
 }
 return members,nil
}
func trimBundleSpace(b []byte)[]byte{return bytes.Trim(b," \t\r\n")}

// nextPEM restricts pem.Decode to exactly the first complete block, so a
// malformed earlier block cannot be silently skipped by the standard decoder.
func nextBundlePEM(raw []byte)(*pem.Block,[]byte,error){
 raw=trimBundleSpace(raw)
 kind:=""
 for _,k:=range []string{"CERTIFICATE","PKCS7"}{
  if bytes.HasPrefix(raw,[]byte("-----BEGIN "+k+"-----\n"))||bytes.HasPrefix(raw,[]byte("-----BEGIN "+k+"-----\r\n")){kind=k;break}
 }
 if kind==""{return nil,nil,errors.New("only CERTIFICATE or PKCS7 PEM accepted")}
 end:=[]byte("\n-----END "+kind+"-----")
 n:=bytes.Index(raw,end)
 if n<0{return nil,nil,errors.New("missing PEM footer")}
 stop:=n+len(end)
 if stop<len(raw)&&raw[stop]!='\r'&&raw[stop]!='\n'{return nil,nil,errors.New("invalid PEM footer boundary")}
 segment:=raw[:stop]
 if bytes.Count(segment,[]byte("-----BEGIN "))!=1||bytes.Count(segment,[]byte("-----END "))!=1{return nil,nil,errors.New("nested or malformed PEM")}
 block,rest:=pem.Decode(append(bytes.Clone(segment),'\n'))
 if block==nil||block.Type!=kind||len(block.Headers)!=0||len(trimBundleSpace(rest))!=0{return nil,nil,errors.New("invalid PEM block")}
 return block,trimBundleSpace(raw[stop:]),nil
}

// ParseCertificateBundle accepts only CA certificates. It preserves input
// order, rejects duplicates and never establishes path or trust.
func ParseCertificateBundle(raw []byte)(string,[]BundleCertificate,error){
 if len(raw)==0||len(raw)>MaxCertificateBundleBytes{return "",nil,errors.New("bundle size limit")}
 format:="SINGLE_DER"
 members:=[][]byte{}
 if bytes.HasPrefix(trimBundleSpace(raw),[]byte("-----BEGIN ")){
  format="PEM_CERTIFICATES"
  rest:=trimBundleSpace(raw)
  for len(rest)>0{
   if len(members)>=MaxCertificateBundleMembers{return "",nil,errors.New("bundle member limit")}
   block,next,err:=nextBundlePEM(rest);if err!=nil{return "",nil,err}
   if block.Type=="PKCS7"{
    if len(members)!=0||len(next)!=0{return "",nil,errors.New("PKCS7 must be the only PEM block")}
    members,err=certificateOnlyPKCS7(block.Bytes);if err!=nil{return "",nil,err}
    format="PKCS7_PEM_CERTIFICATES_ONLY";break
   }
   members=append(members,block.Bytes);rest=next
  }
 }else{
  // Classify exact ContentInfo by its first field. A normal certificate's
  // first field is a SEQUENCE; no fallback from malformed SignedData.
  outer,rest,err:=takeASN1(raw,0,asn1.TagSequence,true)
  if err!=nil||len(rest)!=0{return "",nil,errors.New("expected one exact DER object")}
  if len(outer.Bytes)>0&&outer.Bytes[0]==0x06{
   members,err=certificateOnlyPKCS7(raw);if err!=nil{return "",nil,err};format="PKCS7_DER_CERTIFICATES_ONLY"
  }else{members=append(members,raw)}
 }
 if len(members)==0||len(members)>MaxCertificateBundleMembers{return "",nil,errors.New("invalid member count")}
 out:=make([]BundleCertificate,0,len(members))
 seen:=map[string]bool{}
 for i,der:=range members{
  if len(der)==0||len(der)>MaxCertificateInput{return "",nil,errors.New("certificate member size limit")}
  record,parsed,err:=ParseCertificate(der)
  if err!=nil{return "",nil,fmt.Errorf("member %d: %w",i+1,err)}
  if !bytes.Equal(der,parsed)||!record.IsCA||seen[record.FingerprintSHA256]{return "",nil,errors.New("non-CA, duplicate or non-DER bundle member")}
  seen[record.FingerprintSHA256]=true
  out=append(out,BundleCertificate{record,parsed})
 }
 return format,out,nil
}

// ImportBundleCandidates stores explicitly selected members with the hash of
// the original container as SourceFileSHA256. The caller retains that raw
// container separately. No trust or receipt authenticity is asserted.
func(s *Store)ImportBundleCandidates(raw []byte,source string,at time.Time,selected []string)([]ImportResult,error){
 if s==nil||len(selected)==0||len(selected)>MaxCertificateBundleMembers{return nil,errors.New("explicit bundle member selection required")}
 _,members,err:=ParseCertificateBundle(raw);if err!=nil{return nil,err}
 if err:=validateSourceURL(source);err!=nil{return nil,err}
 if at.IsZero(){return nil,errors.New("observation time required")}
 byID:=map[string]BundleCertificate{};for _,m:=range members{byID[m.Certificate.FingerprintSHA256]=m}
 seen:=map[string]bool{}
 type item struct{record CertificateRecord;provenance ProvenanceRecord;der []byte}
 items:=[]item{}
 for _,fp:=range selected{
  m,ok:=byID[fp]
  if !ok||seen[fp]{return nil,errors.New("unknown or duplicate selected certificate")}
  seen[fp]=true
  record,prov,der,err:=ImportCandidate(m.DER,source,at);if err!=nil{return nil,err}
  prov.SourceFileSHA256=digest(raw)
  if err:=validateImportRecords(record,prov);err!=nil{return nil,err}
  items=append(items,item{record,prov,der})
 }
 if _,err:=s.Validate();err!=nil{return nil,err}
 result:=[]ImportResult{}
 for _,v:=range items{
  imported,err:=s.importRecords(v.record,v.provenance,v.der);if err!=nil{return result,err}
  result=append(result,imported)
 }
 if _,err:=s.Validate();err!=nil{return result,err}
 return result,nil
}
