package snapshot

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "strings"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/validation"
)

type PublicationTransition struct{
 PreviousSHA256 string `json:"previousSHA256"`
 PreviousSequence uint64 `json:"previousSequence"`
 NextSHA256 string `json:"nextSHA256"`
 NextSequence uint64 `json:"nextSequence"`
 HistoryStatus string `json:"historyStatus"`
 Policies validation.TransitionReport `json:"policies"`
 TrustStatus string `json:"trustStatus"`
}
// CheckPublicationTransition is a strict local baseline comparison, not a
// persistent ledger. An expired baseline may be inspected for history only.
// Caller must protect the independent baseline pin and accepted head.
func CheckPublicationTransition(previous,next []byte,pin string,bootstrap bool)(PublicationTransition,error){
 nr,err:=Verify(next,"");if err!=nil{return PublicationTransition{},err}
 var ne Envelope
 if err:=json.Unmarshal(next,&ne);err!=nil{return PublicationTransition{},err}
 result:=PublicationTransition{NextSHA256:nr.SnapshotSHA256,NextSequence:nr.Manifest.Sequence,TrustStatus:"NOT_ESTABLISHED"}
 decode:=func(e Envelope)([]policy.Document,error){
  docs:=[]policy.Document{}
  for _,f:=range e.Payload{if strings.HasPrefix(f.Path,"policies/"){d,err:=policy.DecodeDocument(f.Data);if err!=nil{return nil,err};docs=append(docs,d)}}
  return docs,nil
 }
 nd,err:=decode(ne);if err!=nil{return PublicationTransition{},err}
 noPositive:=func(docs []policy.Document)error{
  for _,d:=range docs{for _,v:=range d.Decisions{if v.Status==policy.Trusted{return errors.New("initial policy collection cannot contain positive authorization")}}}
  return nil
 }
 if bootstrap{
  if len(previous)!=0||pin!=""||nr.Manifest.Sequence!=1{return PublicationTransition{},errors.New("bootstrap requires sequence 1 and no previous baseline")}
  if err:=noPositive(nd);err!=nil{return PublicationTransition{},err}
  result.HistoryStatus="EXPLICIT_BOOTSTRAP_NO_PREVIOUS_BASELINE"
  return result,nil
 }
 if !hashPattern.MatchString(pin)||digest(previous)!=pin{return PublicationTransition{},errors.New("independent previous snapshot pin mismatch")}
 pr,err:=Verify(previous,"");if err!=nil{return PublicationTransition{},err}
 if nr.Manifest.Sequence<=pr.Manifest.Sequence||nr.Manifest.Sequence-pr.Manifest.Sequence!=1||!nr.Manifest.CreatedAt.After(pr.Manifest.CreatedAt){return PublicationTransition{},errors.New("publication sequence must advance exactly once and creation time must increase")}
 var pe Envelope
 if err:=json.Unmarshal(previous,&pe);err!=nil{return PublicationTransition{},err}
 pd,err:=decode(pe);if err!=nil{return PublicationTransition{},err}
 files:=map[string][]byte{}
 for _,f:=range ne.Payload{files[f.Path]=f.Data}
 oldFiles:=map[string]bool{}
 for _,f:=range pe.Payload{
  if strings.HasPrefix(f.Path,"policies/"){continue}
  oldFiles[f.Path]=true
  if !bytes.Equal(f.Data,files[f.Path]){return PublicationTransition{},fmt.Errorf("previous inventory file removed or changed: %s",f.Path)}
 }
 for _,f:=range ne.Payload{
  if strings.HasPrefix(f.Path,"provenance/")&&!oldFiles[f.Path]{
   var v registry.ProvenanceRecord
   if err:=json.Unmarshal(f.Data,&v);err!=nil{return PublicationTransition{},err}
   if !v.RecordedAt.After(pr.Manifest.CreatedAt){return PublicationTransition{},errors.New("new provenance predates previous snapshot")}
  }
 }
 counts:=map[policyKey][2]int{}
 for _,d:=range pd{counts[policyKey{d.Policy.ID,d.Policy.Version}]=[2]int{len(d.Reviews),len(d.Decisions)}}
 // ValidateTransition checks prefixes, scope and positive authorization
 // rules. Also enforce a global recording cutoff for new history events.
 for _,d:=range nd{
  n:=counts[policyKey{d.Policy.ID,d.Policy.Version}]
  if len(d.Reviews)<n[0]||len(d.Decisions)<n[1]{return PublicationTransition{},errors.New("prior policy events omitted")}
  for _,v:=range d.Reviews[n[0]:]{if !v.RecordedAt.After(pr.Manifest.CreatedAt){return PublicationTransition{},errors.New("new review predates previous snapshot")}}
  for _,v:=range d.Decisions[n[1]:]{if !v.RecordedAt.After(pr.Manifest.CreatedAt){return PublicationTransition{},errors.New("new decision predates previous snapshot")}}
 }
 if len(pd)==0{
  if err:=noPositive(nd);err!=nil{return PublicationTransition{},err}
 }else{
  v,err:=loadView(next,nr.Manifest.CreatedAt);if err!=nil{return PublicationTransition{},err}
  err=v.withStore(func(s *registry.Store)error{
   var err error
   result.Policies,err=validation.ValidateTransition(s,pd,nd)
   return err
  });if err!=nil{return PublicationTransition{},err}
 }
 result.PreviousSHA256=pr.SnapshotSHA256;result.PreviousSequence=pr.Manifest.Sequence
 result.HistoryStatus="APPEND_ONLY_PINNED_BASELINE_MATCHED"
 return result,nil
}
