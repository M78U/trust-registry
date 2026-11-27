package snapshot

import (
 "errors"
 "fmt"
 "sort"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
)

const MaxAuthorizationEvaluations=32768
const MaxAuthorizationReportBytes=16<<20

type EvaluationPoint struct{
 At time.Time `json:"at"`
 KnownAt time.Time `json:"knownAt"`
}
type AuthorizationImpactOptions struct{
 PreviousSHA256 string
 NextSHA256 string
 Point EvaluationPoint
 // Optional earlier point evaluated on the previous snapshot only.
 Baseline *EvaluationPoint
}
type AuthorizationState struct{
 Status string `json:"status"`
 DecisionID string `json:"decisionId,omitempty"`
 ReasonCode string `json:"reasonCode"`
 CertificateValidity string `json:"certificateValidity"`
}
type AnchorImpact struct{
 SHA256 string `json:"sha256"`
 Before *AuthorizationState `json:"before,omitempty"`
 After *AuthorizationState `json:"after,omitempty"`
 Change string `json:"change"`
}
type PolicyScope struct{
 Purpose string `json:"purpose"`
 Jurisdiction string `json:"jurisdiction"`
}
type AuthorizationPolicyImpact struct{
 ID string `json:"id"`
 Version int `json:"version"`
 BeforeScope *PolicyScope `json:"beforeScope,omitempty"`
 AfterScope *PolicyScope `json:"afterScope,omitempty"`
 ScopeChanged bool `json:"scopeChanged"`
 BeforeAuthorized int `json:"beforeAuthorized"`
 AfterAuthorized int `json:"afterAuthorized"`
 Changes []AnchorImpact `json:"changes"`
}
type AuthorizationComparison struct{
 Kind string `json:"kind"`
 BeforePoint EvaluationPoint `json:"beforePoint"`
 AfterPoint EvaluationPoint `json:"afterPoint"`
 BeforeSnapshotWindow string `json:"beforeSnapshotWindow"`
 AfterSnapshotWindow string `json:"afterSnapshotWindow"`
 PoliciesCompared int `json:"policiesCompared"`
 AuthorizationGains int `json:"authorizationGains"`
 AuthorizationLosses int `json:"authorizationLosses"`
 OtherAnchorChanges int `json:"otherAnchorChanges"`
 Policies []AuthorizationPolicyImpact `json:"policies"`
}
type AuthorizationImpactReport struct{
 SchemaVersion string `json:"schemaVersion"`
 Kind string `json:"kind"`
 PreviousSHA256 string `json:"previousSHA256"`
 NextSHA256 string `json:"nextSHA256"`
 PreviousSequence uint64 `json:"previousSequence"`
 NextSequence uint64 `json:"nextSequence"`
 SnapshotImpact AuthorizationComparison `json:"snapshotImpact"`
 TimeImpact *AuthorizationComparison `json:"timeImpact,omitempty"`
 AnchorEvaluations int `json:"anchorEvaluations"`
 ReevaluateAffectedPaths bool `json:"reevaluateAffectedPaths"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
 PathStatus string `json:"pathStatus"`
 RevocationStatus string `json:"revocationStatus"`
}
type evaluatedPolicy struct{
 scope PolicyScope
 anchors map[string]AuthorizationState
 authorized int
}
type evaluatedSnapshot struct{
 policies map[policyKey]evaluatedPolicy
 point EvaluationPoint
 window string
}
func validPoint(p EvaluationPoint)bool{return utc(p.At)&&utc(p.KnownAt)&&!p.KnownAt.Before(p.At)}
func snapshotWindow(m Manifest,at time.Time)string{
 if at.Before(m.CreatedAt){return "KNOWLEDGE_TIME_BEFORE_SNAPSHOT_CREATION"}
 if !at.Before(m.ExpiresAt){return "KNOWLEDGE_TIME_AT_OR_AFTER_SNAPSHOT_EXPIRY"}
 return "KNOWLEDGE_TIME_WITHIN_DECLARED_WINDOW"
}
// The evaluator's reason text for a negative decision may contain private
// reviewer text. Only fixed categories are emitted; no free text.
func authorizationReason(a policy.AnchorEvaluation)string{
 switch a.Status{
 case policy.Trusted:return "LOCAL_DECISION_AND_REVIEW_APPLICABLE"
 case policy.Suspended:return "SUSPENSION_APPLICABLE"
 case policy.Distrusted:return "DISTRUST_APPLICABLE"
 }
 switch a.Reason{
 case "no applicable decision":return "NO_APPLICABLE_DECISION"
 case "latest decision expired; older decisions do not resume":return "LATEST_DECISION_EXPIRED"
 case "fresh review and authorization required after restriction":return "FRESH_REVIEW_REQUIRED_AFTER_RESTRICTION"
 case "positive decision evidence rejected or superseded":return "EVIDENCE_REJECTED_OR_SUPERSEDED"
 default:return "OTHER_NOT_ESTABLISHED"
 }
}
func evaluateImpactView(v *Loaded,m Manifest,p EvaluationPoint,budget *int)(evaluatedSnapshot,error){
 result:=evaluatedSnapshot{policies:map[policyKey]evaluatedPolicy{},point:p,window:snapshotWindow(m,p.KnownAt)}
 for k,raw:=range v.policies{
  d,err:=policy.DecodeDocument(raw);if err!=nil{return evaluatedSnapshot{},err}
  // Charge all declared anchors, even unchanged ones.
  if len(d.Policy.TrustAnchors)>*budget{return evaluatedSnapshot{},errors.New("authorization evaluation budget exceeded")}
  *budget-=len(d.Policy.TrustAnchors)
  ev,err:=d.EvaluateAgainst(v.index,p.At,p.KnownAt);if err!=nil{return evaluatedSnapshot{},err}
  row:=evaluatedPolicy{scope:PolicyScope{Purpose:d.Policy.Purpose,Jurisdiction:d.Policy.Jurisdiction},anchors:map[string]AuthorizationState{},authorized:len(ev.LocallyAuthorizedAnchors)}
  for _,a:=range ev.AnchorEvaluations{
   cert,err:=v.index.Find(a.FingerprintSHA256);if err!=nil{return evaluatedSnapshot{},err}
   validity:="WITHIN_VALIDITY"
   if cert.NotAfter.Before(cert.NotBefore){validity="INVALID_VALIDITY_INTERVAL"}else if p.At.Before(cert.NotBefore){validity="NOT_YET_VALID"}else if p.At.After(cert.NotAfter){validity="EXPIRED"}
   row.anchors[a.FingerprintSHA256]=AuthorizationState{Status:a.Status,DecisionID:a.DecisionID,ReasonCode:authorizationReason(a),CertificateValidity:validity}
  }
  result.policies[k]=row
 }
 return result,nil
}
func authorizationComparison(kind string,a,b evaluatedSnapshot)AuthorizationComparison{
 out:=AuthorizationComparison{Kind:kind,BeforePoint:a.point,AfterPoint:b.point,BeforeSnapshotWindow:a.window,AfterSnapshotWindow:b.window,Policies:[]AuthorizationPolicyImpact{}}
 seen:=map[policyKey]bool{}
 for k:=range a.policies{seen[k]=true};for k:=range b.policies{seen[k]=true}
 keys:=make([]policyKey,0,len(seen));for k:=range seen{keys=append(keys,k)}
 sort.Slice(keys,func(i,j int)bool{if keys[i].id==keys[j].id{return keys[i].version<keys[j].version};return keys[i].id<keys[j].id})
 out.PoliciesCompared=len(keys)
 for _,k:=range keys{
  x,ok:=a.policies[k];y,exists:=b.policies[k]
  row:=AuthorizationPolicyImpact{ID:k.id,Version:k.version,BeforeAuthorized:x.authorized,AfterAuthorized:y.authorized,ScopeChanged:!ok||!exists||x.scope!=y.scope,Changes:[]AnchorImpact{}}
  if ok{scope:=x.scope;row.BeforeScope=&scope};if exists{scope:=y.scope;row.AfterScope=&scope}
  for _,fp:=range unionKeys(x.anchors,y.anchors){
   old,had:=x.anchors[fp];next,has:=y.anchors[fp]
   if had&&has&&old==next&&!row.ScopeChanged{continue}
   change:=AnchorImpact{SHA256:fp,Change:"OTHER_LOCAL_STATE_CHANGE"}
   if had{change.Before=&old};if has{change.After=&next}
   // Never compare positive authorizations across different purpose or
   // jurisdiction as equivalent. Report a scope change separately.
   switch{
   case had&&has&&row.ScopeChanged:change.Change="SCOPE_CHANGED";out.OtherAnchorChanges++
   case old.Status!=policy.Trusted&&next.Status==policy.Trusted:change.Change="LOCAL_AUTHORIZATION_GAINED";out.AuthorizationGains++
   case old.Status==policy.Trusted&&next.Status!=policy.Trusted:change.Change="LOCAL_AUTHORIZATION_LOST";out.AuthorizationLosses++
   default:
    if !had{change.Change="ANCHOR_DECLARATION_ADDED"}else if !has{change.Change="ANCHOR_DECLARATION_REMOVED"}else if old.CertificateValidity!=next.CertificateValidity&&old.Status==next.Status&&old.DecisionID==next.DecisionID&&old.ReasonCode==next.ReasonCode{change.Change="CERTIFICATE_VALIDITY_CHANGED"}
    out.OtherAnchorChanges++
   }
   row.Changes=append(row.Changes,change)
  }
  if row.ScopeChanged||len(row.Changes)>0{out.Policies=append(out.Policies,row)}
 }
 return out
}
func loadImpact(raw []byte,pin string,at time.Time)(*Loaded,Report,error){
 if len(raw)==0||len(raw)>MaxEnvelopeBytes||!hashPattern.MatchString(pin)||digest(raw)!=pin{return nil,Report{},errors.New("independent snapshot pin mismatch")}
 r,err:=Verify(raw,"");if err!=nil{return nil,Report{},err}
 // Historical analysis may use an expired snapshot, or a snapshot that
 // was not yet available at the requested knowledge time. Label this
 // explicitly; do not install or claim historical availability.
 v,err:=loadView(raw,at);if err!=nil{return nil,Report{},err}
 return v,r,nil
}
// CompareAuthorization evaluates exact policy versions under identical
// cutoffs, with optional earlier-to-later comparison on the old snapshot.
// This is a counterfactual local-policy diagnostic, not release validation.
func CompareAuthorization(previous,next []byte,o AuthorizationImpactOptions)(AuthorizationImpactReport,error){
 if !validPoint(o.Point){return AuthorizationImpactReport{},errors.New("explicit UTC evaluation and knowledge times required")}
 if o.Baseline!=nil&&(!validPoint(*o.Baseline)||o.Baseline.At.After(o.Point.At)||o.Baseline.KnownAt.After(o.Point.KnownAt)){return AuthorizationImpactReport{},errors.New("baseline times must not exceed target times")}
 a,ar,err:=loadImpact(previous,o.PreviousSHA256,o.Point.KnownAt);if err!=nil{return AuthorizationImpactReport{},fmt.Errorf("previous: %w",err)}
 b,br,err:=loadImpact(next,o.NextSHA256,o.Point.KnownAt);if err!=nil{return AuthorizationImpactReport{},fmt.Errorf("next: %w",err)}
 if br.Manifest.Sequence<=ar.Manifest.Sequence||!br.Manifest.CreatedAt.After(ar.Manifest.CreatedAt){return AuthorizationImpactReport{},errors.New("next sequence and creation time must increase")}
 budget:=MaxAuthorizationEvaluations
 oldNow,err:=evaluateImpactView(a,ar.Manifest,o.Point,&budget);if err!=nil{return AuthorizationImpactReport{},err}
 newNow,err:=evaluateImpactView(b,br.Manifest,o.Point,&budget);if err!=nil{return AuthorizationImpactReport{},err}
 result:=AuthorizationImpactReport{SchemaVersion:"1",Kind:"LOCAL_POLICY_AUTHORIZATION_IMPACT",PreviousSHA256:ar.SnapshotSHA256,NextSHA256:br.SnapshotSHA256,PreviousSequence:ar.Manifest.Sequence,NextSequence:br.Manifest.Sequence,SnapshotImpact:authorizationComparison("SAME_CUTOFF_DIFFERENT_SNAPSHOT",oldNow,newNow),ReevaluateAffectedPaths:true,TrustStatus:"NOT_ESTABLISHED",PathStatus:"NOT_CHECKED",RevocationStatus:"NOT_CHECKED"}
 if o.Baseline!=nil{
  oldEarlier,err:=evaluateImpactView(a,ar.Manifest,*o.Baseline,&budget);if err!=nil{return AuthorizationImpactReport{},err}
  v:=authorizationComparison("SAME_SNAPSHOT_DIFFERENT_CUTOFF",oldEarlier,oldNow);result.TimeImpact=&v
 }
 result.AnchorEvaluations=MaxAuthorizationEvaluations-budget
 raw,err:=canonical(result);if err!=nil{return AuthorizationImpactReport{},err}
 if len(raw)>MaxAuthorizationReportBytes{return AuthorizationImpactReport{},errors.New("authorization impact report size limit")}
 return result,nil
}
