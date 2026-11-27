package policy

import (
 "errors"
 "sort"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
)

type DecisionEvent struct {
 Decision Decision `json:"decision"`
 TemporalStatus string `json:"temporalStatus"`
}
type ReviewEvent struct {
 Review Review `json:"review"`
 KnowledgeStatus string `json:"knowledgeStatus"`
}
type HistoryReport struct {
 PolicyID string `json:"policyId"`
 PolicyVersion int `json:"policyVersion"`
 Purpose string `json:"purpose"`
 CertificateSHA256 string `json:"certificateSHA256"`
 EvaluationTime time.Time `json:"evaluationTime"`
 KnowledgeTime time.Time `json:"knowledgeTime"`
 Current AnchorEvaluation `json:"current"`
 Decisions []DecisionEvent `json:"decisions"`
 Reviews []ReviewEvent `json:"reviews"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}

// History exposes the time-visible events for one declared anchor in one
// exact policy version. Future-recorded events are never included. Current
// authorization comes from Evaluate, not an independent history rule.
func(d Document)History(s *registry.Store,fp string,at,knownAt time.Time)(HistoryReport,error){
 if !fingerprintPattern.MatchString(fp){return HistoryReport{},errors.New("explicit lowercase certificate fingerprint required")}
 evaluation,err:=d.Evaluate(s,at,knownAt);if err!=nil{return HistoryReport{},err}
 var current *AnchorEvaluation
 for _,row:=range evaluation.AnchorEvaluations{if row.FingerprintSHA256==fp{v:=row;current=&v;break}}
 if current==nil{return HistoryReport{},errors.New("certificate is not a declared anchor in this policy version")}
 result:=HistoryReport{PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Purpose:d.Policy.Purpose,CertificateSHA256:fp,EvaluationTime:at,KnowledgeTime:knownAt,Current:*current,Decisions:[]DecisionEvent{},Reviews:[]ReviewEvent{},TrustStatus:Unknown}
 for _,v:=range d.Decisions{
  if v.CertificateSHA256!=fp||v.RecordedAt.After(knownAt){continue}
  status:="SUPERSEDED"
  switch{
  case v.EffectiveFrom.After(at):status="SCHEDULED"
  case v.ID==current.DecisionID:
   if v.EffectiveUntil!=nil&&!at.Before(*v.EffectiveUntil){status="LATEST_EXPIRED"}else{status="LATEST_APPLICABLE"}
  }
  // Clone all mutable fields so the returned report cannot mutate input.
  v.EvidenceIDs=append([]string{},v.EvidenceIDs...)
  v.ReviewReferences=append([]string{},v.ReviewReferences...)
  if v.EffectiveUntil!=nil{t:=*v.EffectiveUntil;v.EffectiveUntil=&t}
  result.Decisions=append(result.Decisions,DecisionEvent{v,status})
 }
 latest:=map[string]Review{}
 for _,v:=range d.Reviews{
  if v.CertificateSHA256!=fp||v.RecordedAt.After(knownAt){continue}
  old,ok:=latest[v.ProvenanceID];if !ok||v.RecordedAt.After(old.RecordedAt){latest[v.ProvenanceID]=v}
 }
 for _,v:=range d.Reviews{
  if v.CertificateSHA256!=fp||v.RecordedAt.After(knownAt){continue}
  status:="SUPERSEDED";if latest[v.ProvenanceID].ID==v.ID{status="LATEST_AS_KNOWN"}
  v.Evidence=append([]string{},v.Evidence...);v.ReviewReferences=append([]string{},v.ReviewReferences...)
  result.Reviews=append(result.Reviews,ReviewEvent{v,status})
 }
 sort.Slice(result.Decisions,func(i,j int)bool{
  a,b:=result.Decisions[i].Decision,result.Decisions[j].Decision
  if !a.EffectiveFrom.Equal(b.EffectiveFrom){return a.EffectiveFrom.Before(b.EffectiveFrom)}
  return a.ID<b.ID
 })
 sort.Slice(result.Reviews,func(i,j int)bool{
  a,b:=result.Reviews[i].Review,result.Reviews[j].Review
  if !a.RecordedAt.Equal(b.RecordedAt){return a.RecordedAt.Before(b.RecordedAt)}
  return a.ID<b.ID
 })
 return result,nil
}
