package snapshot

import (
 "encoding/json"
 "errors"
 "fmt"
 "sort"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/emmansun/gmsm/smx509"
)

const MaxDiffChanges=16384
const MaxDiffReportBytes=16<<20

type DiffOptions struct{
 PreviousSHA256 string
 NextSHA256 string
 RequirePublicationTransition bool
}
type DiffVersion struct{
 SHA256 string `json:"sha256"`
 Sequence uint64 `json:"sequence"`
 CreatedAt time.Time `json:"createdAt"`
 ExpiresAt time.Time `json:"expiresAt"`
 Certificates int `json:"certificates"`
 ProvenanceRecords int `json:"provenanceRecords"`
 PolicyDocuments int `json:"policyDocuments"`
 ConsumerEligibleCandidates int `json:"consumerEligibleCandidates"`
 ConsumerEligibleDERBytes int `json:"consumerEligibleDERBytes"`
 UnfilteredCandidateBudgetExceeded bool `json:"unfilteredCandidateBudgetExceeded"`
}
type CertificateChange struct{
 SHA256 string `json:"sha256"`
 Change string `json:"change"`
 ConsumerEligibleBefore bool `json:"consumerEligibleBefore"`
 ConsumerEligibleAfter bool `json:"consumerEligibleAfter"`
 AddedProvenanceIDs []string `json:"addedProvenanceIds"`
 RemovedProvenanceIDs []string `json:"removedProvenanceIds"`
}
type EventDescriptor struct{
 SHA256 string `json:"sha256"`
 CertificateSHA256 string `json:"certificateSHA256"`
 Status string `json:"status"`
 RecordedAt time.Time `json:"recordedAt"`
 EffectiveFrom *time.Time `json:"effectiveFrom,omitempty"`
 EffectiveUntil *time.Time `json:"effectiveUntil,omitempty"`
}
type EventChange struct{
 ID string `json:"id"`
 Change string `json:"change"`
 Before *EventDescriptor `json:"before,omitempty"`
 After *EventDescriptor `json:"after,omitempty"`
}
type PolicyChange struct{
 ID string `json:"id"`
 Version int `json:"version"`
 Change string `json:"change"`
 BeforeSHA256 string `json:"beforeSHA256,omitempty"`
 AfterSHA256 string `json:"afterSHA256,omitempty"`
 DeclarationChanged bool `json:"declarationChanged"`
 AddedAnchorDeclarations []string `json:"addedAnchorDeclarations"`
 RemovedAnchorDeclarations []string `json:"removedAnchorDeclarations"`
 AddedIntermediateDeclarations []string `json:"addedIntermediateDeclarations"`
 RemovedIntermediateDeclarations []string `json:"removedIntermediateDeclarations"`
 Reviews []EventChange `json:"reviews"`
 Decisions []EventChange `json:"decisions"`
}
type ConsumerImpact struct{
 AddedEligibleCandidates []string `json:"addedEligibleCandidates"`
 RemovedEligibleCandidates []string `json:"removedEligibleCandidates"`
 EligibleCandidatesWithChangedProvenance []string `json:"eligibleCandidatesWithChangedProvenance"`
 PolicyChangesPresent bool `json:"policyChangesPresent"`
 CandidateExportLimitsExceeded bool `json:"candidateExportLimitsExceeded"`
 RefreshCandidateBundles bool `json:"refreshCandidateBundles"`
 ReevaluateAffectedPaths bool `json:"reevaluateAffectedPaths"`
 EffectiveAuthorizationStatus string `json:"effectiveAuthorizationStatus"`
 Status string `json:"status"`
}
type DiffReport struct{
 SchemaVersion string `json:"schemaVersion"`
 Kind string `json:"kind"`
 Previous DiffVersion `json:"previous"`
 Next DiffVersion `json:"next"`
 CertificateChanges []CertificateChange `json:"certificateChanges"`
 PolicyChanges []PolicyChange `json:"policyChanges"`
 Impact ConsumerImpact `json:"consumerImpact"`
 Transition *PublicationTransition `json:"publicationTransition,omitempty"`
 TransitionStatus string `json:"transitionStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}
type diffCert struct{
 eligible bool
 provenance []string
}
type diffPolicy struct{
 doc policy.Document
 hash string
}
type diffState struct{
 version DiffVersion
 certs map[string]diffCert
 policies map[policyKey]diffPolicy
}
func diffLoad(raw []byte,pin string)(diffState,error){
 if len(raw)==0||len(raw)>MaxEnvelopeBytes||!hashPattern.MatchString(pin)||digest(raw)!=pin{return diffState{},errors.New("independent snapshot pin mismatch")}
 r,err:=Verify(raw,"");if err!=nil{return diffState{},err}
 var env Envelope
 if err:=json.Unmarshal(raw,&env);err!=nil{return diffState{},err}
 s:=diffState{version:DiffVersion{SHA256:pin,Sequence:r.Manifest.Sequence,CreatedAt:r.Manifest.CreatedAt,ExpiresAt:r.Manifest.ExpiresAt,Certificates:r.Validation.Certificates,ProvenanceRecords:r.Validation.ProvenanceRecords,PolicyDocuments:r.Validation.PolicyDocuments},certs:map[string]diffCert{},policies:map[policyKey]diffPolicy{}}
 for _,f:=range env.Payload{
  switch{
  case strings.HasPrefix(f.Path,"certificates/")&&strings.HasSuffix(f.Path,".der"):
   fp:=strings.TrimSuffix(strings.TrimPrefix(f.Path,"certificates/"),".der")
   c,err:=smx509.ParseCertificate(f.Data);if err!=nil{return diffState{},err}
   v:=diffCert{eligible:consumerEligible(c),provenance:[]string{}}
   s.certs[fp]=v
   if v.eligible{s.version.ConsumerEligibleCandidates++;s.version.ConsumerEligibleDERBytes+=len(f.Data)}
  case strings.HasPrefix(f.Path,"provenance/"):
   var prov registry.ProvenanceRecord
   if err:=json.Unmarshal(f.Data,&prov);err!=nil{return diffState{},err}
   v,ok:=s.certs[prov.CertificateSHA256];if !ok{return diffState{},errors.New("missing provenance certificate")}
   v.provenance=append(v.provenance,digest(f.Data));s.certs[prov.CertificateSHA256]=v
  case strings.HasPrefix(f.Path,"policies/"):
   d,err:=policy.DecodeDocument(f.Data);if err!=nil{return diffState{},err}
   s.policies[policyKey{d.Policy.ID,d.Policy.Version}]=diffPolicy{d,digest(f.Data)}
  }
 }
 s.version.UnfilteredCandidateBudgetExceeded=s.version.ConsumerEligibleCandidates>MaxConsumerCandidates||s.version.ConsumerEligibleDERBytes>MaxConsumerDERBytes
 for _,v:=range s.certs{if v.eligible&&len(v.provenance)>256{s.version.UnfilteredCandidateBudgetExceeded=true}}
 return s,nil
}
func unionKeys[V any](a,b map[string]V)[]string{
 seen:=map[string]bool{};for k:=range a{seen[k]=true};for k:=range b{seen[k]=true}
 keys:=make([]string,0,len(seen));for k:=range seen{keys=append(keys,k)};sort.Strings(keys);return keys
}
func addedRemoved(a,b []string)(added,removed []string){
 old,next:=map[string]bool{},map[string]bool{}
 for _,v:=range a{old[v]=true};for _,v:=range b{next[v]=true}
 added,removed=[]string{},[]string{}
 for v:=range next{if !old[v]{added=append(added,v)}}
 for v:=range old{if !next[v]{removed=append(removed,v)}}
 sort.Strings(added);sort.Strings(removed);return
}
func eventDescriptors(d policy.Document)(map[string]EventDescriptor,map[string]EventDescriptor,error){
 reviews,decisions:=map[string]EventDescriptor{},map[string]EventDescriptor{}
 for _,v:=range d.Reviews{
  raw,err:=canonical(v);if err!=nil{return nil,nil,err}
  reviews[v.ID]=EventDescriptor{SHA256:digest(raw),CertificateSHA256:v.CertificateSHA256,Status:v.Status,RecordedAt:v.RecordedAt}
 }
 for _,v:=range d.Decisions{
  raw,err:=canonical(v);if err!=nil{return nil,nil,err}
  from:=v.EffectiveFrom
  decisions[v.ID]=EventDescriptor{SHA256:digest(raw),CertificateSHA256:v.CertificateSHA256,Status:v.Status,RecordedAt:v.RecordedAt,EffectiveFrom:&from,EffectiveUntil:v.EffectiveUntil}
 }
 return reviews,decisions,nil
}
func eventChanges(a,b map[string]EventDescriptor,budget *int)([]EventChange,error){
 out:=[]EventChange{}
 for _,id:=range unionKeys(a,b){
  before,ok:=a[id];after,exists:=b[id]
  if ok&&exists&&before.SHA256==after.SHA256{continue}
  if *budget<=0{return nil,errors.New("diff change budget exceeded")};*budget--
  row:=EventChange{ID:id,Change:"MODIFIED"}
  if ok{row.Before=&before}else{row.Change="ADDED"}
  if exists{row.After=&after}else{row.Change="REMOVED"}
  out=append(out,row)
 }
 return out,nil
}
func diffPolicyChanges(a,b diffState,budget *int)([]PolicyChange,error){
 seen:=map[policyKey]bool{}
 for k:=range a.policies{seen[k]=true};for k:=range b.policies{seen[k]=true}
 keys:=make([]policyKey,0,len(seen));for k:=range seen{keys=append(keys,k)}
 sort.Slice(keys,func(i,j int)bool{if keys[i].id==keys[j].id{return keys[i].version<keys[j].version};return keys[i].id<keys[j].id})
 out:=[]PolicyChange{}
 for _,k:=range keys{
  x,ok:=a.policies[k];y,exists:=b.policies[k]
  if ok&&exists&&x.hash==y.hash{continue}
  if *budget<=0{return nil,errors.New("diff change budget exceeded")};*budget--
  row:=PolicyChange{ID:k.id,Version:k.version,Change:"MODIFIED",BeforeSHA256:x.hash,AfterSHA256:y.hash}
  if !ok{row.Change="ADDED"}else if !exists{row.Change="REMOVED"}
  oldDecl,err:=canonical(x.doc.Policy);if err!=nil{return nil,err}
  newDecl,err:=canonical(y.doc.Policy);if err!=nil{return nil,err}
  row.DeclarationChanged=!ok||!exists||digest(oldDecl)!=digest(newDecl)
  row.AddedAnchorDeclarations,row.RemovedAnchorDeclarations=addedRemoved(x.doc.Policy.TrustAnchors,y.doc.Policy.TrustAnchors)
  row.AddedIntermediateDeclarations,row.RemovedIntermediateDeclarations=addedRemoved(x.doc.Policy.IntermediateCandidates,y.doc.Policy.IntermediateCandidates)
  refs:=len(row.AddedAnchorDeclarations)+len(row.RemovedAnchorDeclarations)+len(row.AddedIntermediateDeclarations)+len(row.RemovedIntermediateDeclarations)
  if refs>*budget{return nil,errors.New("diff declaration change budget exceeded")};*budget-=refs
  ar,ad,err:=eventDescriptors(x.doc);if err!=nil{return nil,err}
  br,bd,err:=eventDescriptors(y.doc);if err!=nil{return nil,err}
  row.Reviews,err=eventChanges(ar,br,budget);if err!=nil{return nil,err}
  row.Decisions,err=eventChanges(ad,bd,budget);if err!=nil{return nil,err}
  out=append(out,row)
 }
 return out,nil
}

// Compare compares exact independently pinned research snapshots. It
// verifies both inventories and policy documents; it does not authenticate
// releases, decide effective authorization or validate any consumer path.
func Compare(previous,next []byte,o DiffOptions)(DiffReport,error){
 a,err:=diffLoad(previous,o.PreviousSHA256);if err!=nil{return DiffReport{},fmt.Errorf("previous: %w",err)}
 b,err:=diffLoad(next,o.NextSHA256);if err!=nil{return DiffReport{},fmt.Errorf("next: %w",err)}
 if b.version.Sequence<=a.version.Sequence||!b.version.CreatedAt.After(a.version.CreatedAt){return DiffReport{},errors.New("next sequence and creation time must increase")}
 r:=DiffReport{SchemaVersion:"1",Kind:"LOCAL_PINNED_REGISTRY_DIFF",Previous:a.version,Next:b.version,CertificateChanges:[]CertificateChange{},PolicyChanges:[]PolicyChange{},TransitionStatus:"NOT_CHECKED",TrustStatus:"NOT_ESTABLISHED"}
 r.Impact=ConsumerImpact{AddedEligibleCandidates:[]string{},RemovedEligibleCandidates:[]string{},EligibleCandidatesWithChangedProvenance:[]string{},CandidateExportLimitsExceeded:b.version.UnfilteredCandidateBudgetExceeded,RefreshCandidateBundles:true,ReevaluateAffectedPaths:true,EffectiveAuthorizationStatus:"NOT_EVALUATED",Status:"POTENTIAL_IMPACT_ONLY"}
 budget:=MaxDiffChanges
 for _,fp:=range unionKeys(a.certs,b.certs){
  old,ok:=a.certs[fp];new,exists:=b.certs[fp]
  added,removed:=addedRemoved(old.provenance,new.provenance)
  if ok&&exists&&len(added)==0&&len(removed)==0{continue}
  cost:=1+len(added)+len(removed);if cost>budget{return DiffReport{},errors.New("diff certificate change budget exceeded")};budget-=cost
  row:=CertificateChange{SHA256:fp,Change:"PROVENANCE_CHANGED",ConsumerEligibleBefore:old.eligible,ConsumerEligibleAfter:new.eligible,AddedProvenanceIDs:added,RemovedProvenanceIDs:removed}
  if !ok{row.Change="ADDED"}else if !exists{row.Change="REMOVED"}
  if new.eligible&&!old.eligible{r.Impact.AddedEligibleCandidates=append(r.Impact.AddedEligibleCandidates,fp)}
  if old.eligible&&!new.eligible{r.Impact.RemovedEligibleCandidates=append(r.Impact.RemovedEligibleCandidates,fp)}
  if old.eligible&&new.eligible{r.Impact.EligibleCandidatesWithChangedProvenance=append(r.Impact.EligibleCandidatesWithChangedProvenance,fp)}
  r.CertificateChanges=append(r.CertificateChanges,row)
 }
 r.PolicyChanges,err=diffPolicyChanges(a,b,&budget);if err!=nil{return DiffReport{},err}
 r.Impact.PolicyChangesPresent=len(r.PolicyChanges)>0
 if o.RequirePublicationTransition{
  v,err:=CheckPublicationTransition(previous,next,o.PreviousSHA256,false);if err!=nil{return DiffReport{},err}
  r.Transition=&v;r.TransitionStatus=v.HistoryStatus
 }
 raw,err:=canonical(r);if err!=nil{return DiffReport{},err}
 if len(raw)>MaxDiffReportBytes{return DiffReport{},errors.New("diff report size limit")}
 return r,nil
}
