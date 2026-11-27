package validation

import (
 "errors"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/revocation"
)

const MaxRevocationPairs=128
type ChainRevocation struct {
 ChainSHA256 []string `json:"chainSHA256"`
 PairIndices []int `json:"pairIndices"`
 Status string `json:"status"`
 HistoricalRevokedIndication bool `json:"historicalRevokedIndication"`
}
type PathRevocation struct{
 Status string `json:"status"`
 Scope string `json:"scope"`
 ObservationCutoff time.Time `json:"observationCutoff"`
 HistoricalRevokedIndication bool `json:"historicalRevokedIndication"`
 Observations []revocation.EvidenceRecord `json:"observations"`
 Pairs []revocation.Report `json:"pairs"`
 Chains []ChainRevocation `json:"chains"`
}
type LocalPathWithRevocationReport struct{
 LocalPathReport
 Revocation PathRevocation `json:"revocation"`
}
func strongest(a,b string)string{
 rank:=func(s string)int{switch s{
 case "REVOKED_IN_SUPPLIED_EVIDENCE":return 4
 case "CONFLICTING_SUPPLIED_EVIDENCE":return 3
 case "INCOMPLETE_SUPPLIED_EVIDENCE":return 2
 case "NON_REVOKED_INDICATIONS_ONLY":return 1
 default:return 0
 }}
 if rank(b)>rank(a){return b};return a
}

// VerifyLocalPathWithRevocation validates the original exact policy path,
// then independently examines all returned chains (excluding each anchor).
// Aggregate status is the worst observed risk, not a chosen trust path.
func VerifyLocalPathWithRevocation(s *registry.Store,d policy.Document,input []byte,purpose,dnsName string,at,knownAt time.Time,evidence *revocation.EvidenceStore)(LocalPathWithRevocationReport,error){
 set,err:=evidence.Load(knownAt);if err!=nil{return LocalPathWithRevocationReport{},err}
 local,err:=VerifyLocalPath(s,d,input,purpose,dnsName,at,knownAt);if err!=nil{return LocalPathWithRevocationReport{},err}
 out:=LocalPathWithRevocationReport{LocalPathReport:local,Revocation:PathRevocation{Status:"NO_VALID_PATH",Scope:"ALL_RETURNED_TECHNICAL_PATHS_WORST_RISK_EXCLUDING_ANCHORS_NO_FRESHNESS_OR_RECEIPT_PROOF",ObservationCutoff:knownAt,Observations:set.Records(),Pairs:[]revocation.Report{},Chains:[]ChainRevocation{}}}
 if local.Path.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"{return out,nil}
 leaf,der,err:=registry.ParseCertificate(input);if err!=nil{return LocalPathWithRevocationReport{},err}
 if leaf.FingerprintSHA256!=local.Path.LeafSHA256{return LocalPathWithRevocationReport{},errors.New("leaf changed during verification")}
 cache:=map[string][]byte{leaf.FingerprintSHA256:der}
 total:=len(der)
 read:=func(fp string)([]byte,error){
  if v,ok:=cache[fp];ok{return v,nil}
  v,err:=s.ReadCertificateDER(fp);if err!=nil{return nil,err}
  if len(v)>registry.MaxGraphDERBytes-total{return nil,errors.New("revocation path DER budget exceeded")}
  total+=len(v);cache[fp]=v;return v,nil
 }
 seen:=map[[2]string]int{}
 out.Revocation.Status="NON_REVOKED_INDICATIONS_ONLY"
 for _,chain:=range local.Path.Chains{
  if len(chain)<2||chain[0]!=leaf.FingerprintSHA256{return LocalPathWithRevocationReport{},errors.New("unexpected verified chain")}
  row:=ChainRevocation{ChainSHA256:append([]string{},chain...),PairIndices:[]int{},Status:"NON_REVOKED_INDICATIONS_ONLY"}
  for i:=0;i+1<len(chain);i++{
   k:=[2]string{chain[i],chain[i+1]}
   idx,ok:=seen[k]
   if !ok{
    if len(out.Revocation.Pairs)>=MaxRevocationPairs{return LocalPathWithRevocationReport{},errors.New("revocation pair budget exceeded")}
    c,err:=read(k[0]);if err!=nil{return LocalPathWithRevocationReport{},err}
    issuer,err:=read(k[1]);if err!=nil{return LocalPathWithRevocationReport{},err}
    result,err:=set.EvaluatePair(c,issuer,at);if err!=nil{return LocalPathWithRevocationReport{},err}
    if result.CertificateSHA256!=k[0]||result.IssuerSHA256!=k[1]{return LocalPathWithRevocationReport{},errors.New("revocation pair identity mismatch")}
    idx=len(out.Revocation.Pairs);seen[k]=idx;out.Revocation.Pairs=append(out.Revocation.Pairs,result)
   }
   pair:=out.Revocation.Pairs[idx]
   row.PairIndices=append(row.PairIndices,idx)
   row.Status=strongest(row.Status,pair.Status)
   row.HistoricalRevokedIndication=row.HistoricalRevokedIndication||len(pair.HistoricalIndications)>0
  }
  out.Revocation.Status=strongest(out.Revocation.Status,row.Status)
  out.Revocation.HistoricalRevokedIndication=out.Revocation.HistoricalRevokedIndication||row.HistoricalRevokedIndication
  out.Revocation.Chains=append(out.Revocation.Chains,row)
 }
 if len(out.Revocation.Chains)==0{return LocalPathWithRevocationReport{},errors.New("valid path report without chains")}
 out.Path.RevocationStatus=out.Revocation.Status
 return out,nil
}
