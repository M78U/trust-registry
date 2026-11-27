// Package revocation inspects explicitly supplied offline issuer evidence.
// It does not establish certificate path trust or fetch revocation data.
package revocation

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/emmansun/gmsm/smx509"
)

const maxBundle=16<<20
const MaxEvidenceInput=maxBundle
const MaxOCSPResponses=16

func fingerprint(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
type Options struct {
 At time.Time
 KnownAt time.Time
}
type HistoricalIndication struct{
 Kind string `json:"kind"`
 EvidenceSHA256 string `json:"evidenceSHA256"`
 IssuedAt time.Time `json:"issuedAt"`
 RevocationTime time.Time `json:"revocationTime"`
 TemporalStatus string `json:"temporalStatus"`
}
type Report struct{
 CertificateSHA256 string `json:"certificateSHA256"`
 IssuerSHA256 string `json:"issuerSHA256"`
 EvaluationTime time.Time `json:"evaluationTime"`
 KnowledgeCutoff time.Time `json:"knowledgeCutoff"`
 DirectIssuerStatus string `json:"directIssuerStatus"`
 Status string `json:"status"`
 Conflict bool `json:"conflict"`
 CRLs []CRLCandidate `json:"crls"`
 OCSP []OCSPCandidate `json:"ocsp"`
 HistoricalIndications []HistoricalIndication `json:"historicalIndications"`
 Scope string `json:"scope"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
func validTime(t time.Time)bool{return !t.IsZero()&&t.Location()==time.UTC&&t.Year()>=1&&t.Year()<=9999}

// EvaluatePair first verifies direct issuer identity/signature; this is not
// chain validation. Only evidence issued no later than KnownAt is considered.
// That cutoff is based on signed timestamps, not independently proven receipt.
func EvaluatePair(input,issuerInput []byte,crls *CRLStore,ocsp *OCSPStore,o Options)(Report,error){
 if !validTime(o.At)||!validTime(o.KnownAt)||o.KnownAt.Before(o.At){return Report{},errors.New("explicit UTC evaluation and knowledge cutoff required")}
 c,der,err:=registry.ParseCertificate(input);if err!=nil{return Report{},err}
 i,issuerDER,err:=registry.ParseCertificate(issuerInput);if err!=nil{return Report{},err}
 child,err:=smx509.ParseCertificate(der);if err!=nil{return Report{},err}
 issuer,err:=smx509.ParseCertificate(issuerDER);if err!=nil{return Report{},err}
 if c.FingerprintSHA256==i.FingerprintSHA256||!issuer.BasicConstraintsValid||!issuer.IsCA||issuer.KeyUsage!=0&&issuer.KeyUsage&smx509.KeyUsageCertSign==0||len(issuer.UnhandledCriticalExtensions)>0||len(child.UnhandledCriticalExtensions)>0||!bytes.Equal(child.RawIssuer,issuer.RawSubject)||len(child.AuthorityKeyId)>0&&len(issuer.SubjectKeyId)>0&&!bytes.Equal(child.AuthorityKeyId,issuer.SubjectKeyId)||child.CheckSignatureFrom(issuer)!=nil{return Report{},errors.New("explicit certificate is not a verified direct child of issuer")}
 r:=Report{CertificateSHA256:c.FingerprintSHA256,IssuerSHA256:i.FingerprintSHA256,EvaluationTime:o.At,KnowledgeCutoff:o.KnownAt,DirectIssuerStatus:"MATCHED_DIRECT_SIGNATURE_ONLY",Status:"NOT_CHECKED",CRLs:[]CRLCandidate{},OCSP:[]OCSPCandidate{},HistoricalIndications:[]HistoricalIndication{},Scope:"EXPLICIT_PAIR_ONLY_NO_PATH_TRUST_FRESHNESS_COVERAGE_OR_RECEIPT_PROOF",TrustStatus:"NOT_ESTABLISHED"}
 if crls==nil&&ocsp==nil{return r,nil}
 absent,good,unknown,revoked:=0,0,0,0
 historic:=func(kind,fp string,issued time.Time,when *time.Time,status string){
  if status!="OUTSIDE_UPDATE_INTERVAL"||when==nil||when.After(o.At)||issued.After(o.KnownAt){return}
  label:="EXPIRED_EVIDENCE";if issued.After(o.At){label="ISSUED_AFTER_EVALUATION_TIME"}
  r.HistoricalIndications=append(r.HistoricalIndications,HistoricalIndication{kind,fp,issued.UTC(),when.UTC(),label})
 }
 if crls!=nil{
  for _,list:=range crls.lists{
   if !bytes.Equal(list.RawIssuer,issuer.RawSubject)||list.ThisUpdate.After(o.KnownAt){continue}
   v:=crls.inspect(list,child,issuer,o.At)
   r.CRLs=append(r.CRLs,v)
   switch v.Status{case "SERIAL_NOT_LISTED":absent++;case "REVOKED_AT_EVALUATION_TIME":revoked++}
   if v.AuthenticatedAssertion=="REVOKED"{historic("CRL",v.CRLSHA256,v.ThisUpdate,v.RevocationTime,v.Status)}
  }
 }
 if ocsp!=nil{
  for _,response:=range ocsp.responses{
   if response.produced.After(o.KnownAt){continue}
   v,matched:=response.inspect(child,issuer,o.At);if !matched{continue}
   r.OCSP=append(r.OCSP,v)
   switch v.Status{case "GOOD_IN_AUTHENTICATED_RESPONSE":good++;case "UNKNOWN_IN_AUTHENTICATED_RESPONSE":unknown++;case "REVOKED_IN_AUTHENTICATED_RESPONSE":revoked++}
   if v.AuthenticatedAssertion=="REVOKED"{historic("OCSP",v.ResponseSHA256,v.ProducedAt,v.RevocationTime,v.Status)}
  }
 }
 r.Conflict=revoked>0&&(good>0||absent>0)||unknown>0&&good>0
 switch{
 case revoked>0:r.Status="REVOKED_IN_SUPPLIED_EVIDENCE"
 case r.Conflict:r.Status="CONFLICTING_SUPPLIED_EVIDENCE"
 case unknown>0||absent>1||good>1||absent+good==0:r.Status="INCOMPLETE_SUPPLIED_EVIDENCE"
 default:r.Status="NON_REVOKED_INDICATIONS_ONLY"
 }
 return r,nil
}
