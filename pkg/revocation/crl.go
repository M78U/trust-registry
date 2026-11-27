package revocation

import (
 "bytes"
 "encoding/asn1"
 "encoding/pem"
 "errors"
 "fmt"
 "math/big"
 "sort"
 "time"

 "github.com/emmansun/gmsm/smx509"
)

const maxCRLs=16
const maxCRLEntries=50000

// CRLStore is explicit, local and shared only as evidence. It cannot add
// trust anchors or change the selected certificate path.
type CRLStore struct{
 lists []*smx509.RevocationList
 fingerprints []string
}
type CRLCandidate struct{
 AuthenticatedAssertion string `json:"authenticatedAssertion,omitempty"`
 CRLSHA256 string `json:"crlSHA256"`
 Status string `json:"status"`
 Reason string `json:"reason,omitempty"`
 ThisUpdate time.Time `json:"thisUpdate"`
 NextUpdate time.Time `json:"nextUpdate"`
 Number string `json:"number,omitempty"`
 RevocationTime *time.Time `json:"revocationTime,omitempty"`
 ReasonCode *int `json:"reasonCode,omitempty"`
}
func (s *CRLStore) Fingerprints()[]string{if s==nil{return nil};return append([]string(nil),s.fingerprints...)}

func LoadCRLBytes(b []byte)(*CRLStore,error){
 if len(b)==0||len(b)>maxBundle{return nil,errors.New("invalid CRL bundle size")}
 return parseCRLs(bytes.Clone(b))
}
func parseCRLs(b []byte)(*CRLStore,error){
 if len(b)==0||len(b)>maxBundle{return nil,errors.New("invalid CRL bundle size")}
 s:=&CRLStore{}
 seen:=map[string]bool{};total:=0
 add:=func(der []byte)error{
  if len(s.lists)>=maxCRLs{return errors.New("CRL count limit")}
  r,e:=smx509.ParseRevocationList(der);if e!=nil{return e}
  if !bytes.Equal(r.Raw,der){return errors.New("trailing CRL data")}
  total+=len(r.RevokedCertificateEntries);if total>maxCRLEntries{return errors.New("CRL entry limit")}
  fp:=fingerprint(der);if seen[fp]{return errors.New("duplicate CRL")};seen[fp]=true
  s.lists=append(s.lists,r);s.fingerprints=append(s.fingerprints,fp)
  return nil
 }
 trim:=bytes.TrimSpace(b)
 if bytes.HasPrefix(trim,[]byte("-----BEGIN ")){
  for len(trim)>0{
   if !bytes.HasPrefix(trim,[]byte("-----BEGIN X509 CRL-----")){return nil,errors.New("unexpected CRL PEM data")}
   const footer="-----END X509 CRL-----"
   n:=bytes.Index(trim,[]byte(footer));if n<0{return nil,errors.New("missing CRL PEM footer")}
   end:=n+len(footer);part:=trim[:end]
   block,rest:=pem.Decode(append(bytes.Clone(part),'\n'))
   if block==nil||block.Type!="X509 CRL"||len(block.Headers)!=0||len(bytes.TrimSpace(rest))!=0||bytes.Count(part,[]byte("-----BEGIN "))!=1{return nil,errors.New("invalid CRL PEM block")}
   if e:=add(block.Bytes);e!=nil{return nil,e};trim=bytes.TrimSpace(trim[end:])
  }
 }else if e:=add(b);e!=nil{return nil,e}
 sort.Strings(s.fingerprints)
 sort.Slice(s.lists,func(i,j int)bool{return fingerprint(s.lists[i].Raw)<fingerprint(s.lists[j].Raw)})
 return s,nil
}

// Strict narrow CRL extension profile. In particular, IDP, delta CRL,
// certificateIssuer and unknown extensions must not be ignored.
func crlProfile(r *smx509.RevocationList)error{
 seen:=map[string]bool{}
 for _,ext:=range r.Extensions{
  id:=ext.Id.String();if seen[id]{return errors.New("duplicate CRL extension")};seen[id]=true
  if ext.Critical{return errors.New("unsupported critical CRL extension")}
  switch id{
  case "2.5.29.35":
   // Only the keyIdentifier form; no ignored authority issuer/serial.
   var aki struct{KeyID []byte `asn1:"tag:0"`}
   rest,e:=asn1.Unmarshal(ext.Value,&aki)
   if e!=nil||len(rest)!=0||len(aki.KeyID)==0||!bytes.Equal(aki.KeyID,r.AuthorityKeyId){return errors.New("unsupported CRL AKI")}
   encoded,e:=asn1.Marshal(aki);if e!=nil||!bytes.Equal(encoded,ext.Value){return errors.New("unsupported CRL AKI fields")}
  case "2.5.29.20":
   var n *big.Int;rest,e:=asn1.Unmarshal(ext.Value,&n)
   if e!=nil||len(rest)!=0||n==nil||n.Sign()<0||n.BitLen()>160||r.Number==nil||n.Cmp(r.Number)!=0{return errors.New("invalid CRL number")}
  default:return fmt.Errorf("unsupported CRL extension %s",id)
  }
 }
 if !seen["2.5.29.35"]||!seen["2.5.29.20"]{return errors.New("CRL AKI and number required")}
 if r.ThisUpdate.IsZero()||!r.NextUpdate.After(r.ThisUpdate){return errors.New("invalid CRL update interval")}
 serials:=map[string]bool{}
 for _,entry:=range r.RevokedCertificateEntries{
  if entry.SerialNumber==nil||entry.SerialNumber.Sign()<=0||entry.SerialNumber.BitLen()>160||entry.RevocationTime.IsZero()||entry.RevocationTime.After(r.ThisUpdate){return errors.New("invalid CRL entry")}
  k:=entry.SerialNumber.Text(16);if serials[k]{return errors.New("duplicate revoked serial")};serials[k]=true
  if len(entry.Extensions)>1{return errors.New("unsupported CRL entry extensions")}
  for _,ext:=range entry.Extensions{
   if ext.Critical||ext.Id.String()!="2.5.29.21"{return errors.New("unsupported CRL entry extension")}
   var reason asn1.Enumerated;rest,e:=asn1.Unmarshal(ext.Value,&reason)
   if e!=nil||len(rest)!=0||int(reason)!=entry.ReasonCode{return errors.New("invalid reason code")}
  }
  switch entry.ReasonCode{case 0,1,2,3,4,5,6,9,10:default:return errors.New("unsupported CRL reason code")}
 }
 return nil
}
func (s *CRLStore) inspect(r *smx509.RevocationList,cert,issuer *smx509.Certificate,at time.Time)CRLCandidate{
 v:=CRLCandidate{CRLSHA256:fingerprint(r.Raw),Status:"REJECTED",ThisUpdate:r.ThisUpdate,NextUpdate:r.NextUpdate}
 if r.Number!=nil{v.Number=r.Number.Text(16)}
 if e:=crlProfile(r);e!=nil{v.Reason=e.Error();return v}
 switch r.SignatureAlgorithm {
 case smx509.SHA256WithRSA,smx509.SHA384WithRSA,smx509.SHA512WithRSA,smx509.ECDSAWithSHA256,smx509.ECDSAWithSHA384,smx509.ECDSAWithSHA512,smx509.SM2WithSM3:
 default:v.Reason="unsupported CRL signature algorithm";return v
 }
 if len(issuer.SubjectKeyId)==0||!bytes.Equal(r.AuthorityKeyId,issuer.SubjectKeyId){v.Reason="issuer key identifier mismatch";return v}
 if !issuer.BasicConstraintsValid||!issuer.IsCA||issuer.KeyUsage&smx509.KeyUsageCRLSign==0{v.Reason="issuer not authorized for CRL signing";return v}
 if e:=r.CheckSignatureFrom(issuer);e!=nil{v.Reason="CRL signature verification failed";return v}
 if r.ThisUpdate.Before(issuer.NotBefore)||r.ThisUpdate.After(issuer.NotAfter){v.Reason="CRL issuer certificate invalid at thisUpdate";return v}
 v.AuthenticatedAssertion="SERIAL_NOT_LISTED"
 for _,entry:=range r.RevokedCertificateEntries{
  if entry.SerialNumber.Cmp(cert.SerialNumber)==0{
   when:=entry.RevocationTime.UTC();reason:=entry.ReasonCode
   v.RevocationTime=&when;v.ReasonCode=&reason
   v.AuthenticatedAssertion="REVOKED";break
  }
 }
 if at.Before(r.ThisUpdate)||!at.Before(r.NextUpdate){v.Status="OUTSIDE_UPDATE_INTERVAL";return v}
 v.Status="SERIAL_NOT_LISTED";if v.AuthenticatedAssertion=="REVOKED"{v.Status="REVOKED_AT_EVALUATION_TIME"}
 return v
}
