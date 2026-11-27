package sources

import (
 "errors"
 "sort"

 "github.com/M78U/trust-registry/pkg/registry"
)

type ArchiveResearchMember struct{
 CertificateSHA256 string `json:"certificateSHA256"`
 MatchStatus string `json:"matchStatus"`
}
type ArchiveCertificateAnalysis struct{
 CertificateSHA256 string `json:"certificateSHA256"`
 Analysis CertificateAnalysis `json:"analysis"`
}
type ArchiveTechnicalEvidence struct{
 Scope string `json:"scope"`
 Graph registry.RelationshipGraph `json:"graph"`
 Analyses []ArchiveCertificateAnalysis `json:"analyses"`
 PathValidation string `json:"pathValidation"`
 PurposeAuthorization string `json:"purposeAuthorization"`
 TrustStatus string `json:"trustStatus"`
}
type archiveTechnicalCollector struct{
 originals map[string][]byte
 total int
}
func newArchiveTechnicalCollector()*archiveTechnicalCollector{
 return &archiveTechnicalCollector{originals:map[string][]byte{}}
}
func(c *archiveTechnicalCollector)add(link *PinnedArchiveLink,raw []byte,expected,status string)error{
 record,der,err:=registry.ParseCertificate(raw);if err!=nil{return err}
 if !record.IsCA||record.FingerprintSHA256!=expected{return errors.New("archive technical certificate identity mismatch")}
 if _,ok:=c.originals[expected];!ok{
  if len(c.originals)>=registry.MaxGraphNodes||len(der)>registry.MaxGraphDERBytes-c.total{return errors.New("archive technical graph budget exceeded")}
  c.originals[expected]=der;c.total+=len(der)
 }
 link.ResearchMembers=append(link.ResearchMembers,ArchiveResearchMember{CertificateSHA256:expected,MatchStatus:status})
 return nil
}
func(c *archiveTechnicalCollector)report()(ArchiveTechnicalEvidence,error){
 ids:=make([]string,0,len(c.originals));for fp:=range c.originals{ids=append(ids,fp)}
 sort.Strings(ids)
 r:=ArchiveTechnicalEvidence{Scope:"EXPLICIT_PINNED_ARCHIVE_CA_MEMBERS_ONLY",Analyses:[]ArchiveCertificateAnalysis{},PathValidation:"NOT_PERFORMED",PurposeAuthorization:"NOT_ESTABLISHED",TrustStatus:"NOT_ESTABLISHED"}
 inputs:=make([][]byte,0,len(ids))
 for _,fp:=range ids{
  der:=c.originals[fp]
  a,err:=analyze(der);if err!=nil{return ArchiveTechnicalEvidence{},err}
  inputs=append(inputs,der)
  r.Analyses=append(r.Analyses,ArchiveCertificateAnalysis{CertificateSHA256:fp,Analysis:a})
 }
 g,err:=registry.ResearchGraph(inputs);if err!=nil{return ArchiveTechnicalEvidence{},err}
 r.Graph=g
 return r,nil
}
