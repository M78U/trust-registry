package validation

import (
 "errors"
 "fmt"
 "sort"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
)

type TransitionReport struct {
 Revisions []policy.RevisionReport `json:"revisions"`
 AddedPolicyVersions []string `json:"addedPolicyVersions"`
 HistoryStatus string `json:"historyStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}

// ValidateTransition compares explicit complete policy collections from two
// revisions. Existing versions may only append events; no omitted versions,
// scope change or insertion of an older version under an existing policy ID.
// New versions are separate explicit policies, not inherited authorizations.
// This is a local comparison, not an authenticated publication ledger.
func ValidateTransition(s *registry.Store,previous,next []policy.Document)(TransitionReport,error){
 if len(previous)==0{return TransitionReport{},errors.New("nonempty previous policy collection required")}
 if _,err:=Validate(s,previous);err!=nil{return TransitionReport{},err}
 if _,err:=Validate(s,next);err!=nil{return TransitionReport{},err}
 index,err:=s.BuildIndex();if err!=nil{return TransitionReport{},err}
 type key struct{id string;version int}
 old:=map[key]policy.Document{}
 maximum:=map[string]int{}
 scopes:=map[string][2]string{}
 for _,d:=range previous{
  p:=d.Policy;old[key{p.ID,p.Version}]=d
  if p.Version>maximum[p.ID]{maximum[p.ID]=p.Version}
  scopes[p.ID]=[2]string{p.Jurisdiction,p.Purpose}
 }
 result:=TransitionReport{Revisions:[]policy.RevisionReport{},AddedPolicyVersions:[]string{},HistoryStatus:"APPEND_ONLY_BASELINE_MATCHED",TrustStatus:policy.Unknown}
 for _,d:=range next{
  p:=d.Policy;k:=key{p.ID,p.Version}
  if prior,ok:=old[k];ok{
   row,err:=policy.CompareRevision(index,prior,d);if err!=nil{return TransitionReport{},fmt.Errorf("%s/%d: %w",p.ID,p.Version,err)}
   result.Revisions=append(result.Revisions,row);delete(old,k)
   continue
  }
  if scope,ok:=scopes[p.ID];ok{
   if scope!=[2]string{p.Jurisdiction,p.Purpose}||p.Version<=maximum[p.ID]{return TransitionReport{},errors.New("new policy version changes scope or inserts historical version")}
  }
  // New policy versions must start without positive authorizations. This
  // prevents a version bump from automatically restoring a restricted anchor.
  // Subsequent new reviews and decisions require their own explicit revision.
  for _,v:=range d.Decisions{if v.Status==policy.Trusted{return TransitionReport{},errors.New("new policy version must not contain pre-authorized anchors")}}
  result.AddedPolicyVersions=append(result.AddedPolicyVersions,fmt.Sprintf("%s/%d",p.ID,p.Version))
 }
 if len(old)>0{return TransitionReport{},errors.New("previous policy version omitted")}
 sort.Slice(result.Revisions,func(i,j int)bool{a,b:=result.Revisions[i],result.Revisions[j];if a.PolicyID!=b.PolicyID{return a.PolicyID<b.PolicyID};return a.PolicyVersion<b.PolicyVersion})
 sort.Strings(result.AddedPolicyVersions)
 return result,nil
}
