package policy

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "reflect"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
)

// RevisionReport compares two exact policy-version documents. Digests refer
// to compact Go JSON plus LF, not Git blobs or authenticated release bytes.
type RevisionReport struct {
 PolicyID string `json:"policyId"`
 PolicyVersion int `json:"policyVersion"`
 PreviousSHA256 string `json:"previousSHA256"`
 NextSHA256 string `json:"nextSHA256"`
 AddedReviews int `json:"addedReviews"`
 AddedDecisions int `json:"addedDecisions"`
 HistoryStatus string `json:"historyStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}

func DocumentBytes(d Document)([]byte,error){
 raw,err:=json.Marshal(d);if err!=nil{return nil,err}
 raw=append(raw,'\n')
 if len(raw)>MaxDocumentBytes{return nil,errors.New("policy document size limit exceeded")}
 return raw,nil
}
func documentHash(d Document)(string,error){
 raw,err:=DocumentBytes(d);if err!=nil{return "",err}
 sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:]),nil
}

// CompareRevision requires the same exact policy definition, unchanged event
// prefixes and strictly newer recording times for appended events. Reordering
// or reusing event IDs is forbidden. Caller supplies a trusted baseline.
func CompareRevision(index *registry.Index,previous,next Document)(RevisionReport,error){
 if err:=previous.ValidateAgainst(index);err!=nil{return RevisionReport{},fmt.Errorf("previous policy: %w",err)}
 if err:=next.ValidateAgainst(index);err!=nil{return RevisionReport{},fmt.Errorf("next policy: %w",err)}
 if !reflect.DeepEqual(previous.Policy,next.Policy){return RevisionReport{},errors.New("policy definition changed; preserve old version and create a new explicit version")}
 if len(next.Reviews)<len(previous.Reviews)||len(next.Decisions)<len(previous.Decisions){return RevisionReport{},errors.New("policy history deleted")}
 var cutoff time.Time
 for i,v:=range previous.Reviews{
  if !reflect.DeepEqual(v,next.Reviews[i]){return RevisionReport{},errors.New("prior review modified or reordered")}
  if v.RecordedAt.After(cutoff){cutoff=v.RecordedAt}
 }
 for i,v:=range previous.Decisions{
  if !reflect.DeepEqual(v,next.Decisions[i]){return RevisionReport{},errors.New("prior decision modified or reordered")}
  if v.RecordedAt.After(cutoff){cutoff=v.RecordedAt}
 }
 for _,v:=range next.Reviews[len(previous.Reviews):]{if !v.RecordedAt.After(cutoff){return RevisionReport{},errors.New("appended review recording time must follow baseline history")}}
 for _,v:=range next.Decisions[len(previous.Decisions):]{if !v.RecordedAt.After(cutoff){return RevisionReport{},errors.New("appended decision recording time must follow baseline history")}}
 oldHash,err:=documentHash(previous);if err!=nil{return RevisionReport{},err}
 newHash,err:=documentHash(next);if err!=nil{return RevisionReport{},err}
 return RevisionReport{PolicyID:next.Policy.ID,PolicyVersion:next.Policy.Version,PreviousSHA256:oldHash,NextSHA256:newHash,AddedReviews:len(next.Reviews)-len(previous.Reviews),AddedDecisions:len(next.Decisions)-len(previous.Decisions),HistoryStatus:"APPEND_ONLY_BASELINE_MATCHED",TrustStatus:Unknown},nil
}

type RestrictionOptions struct {
 ID string
 CertificateSHA256 string
 Status string
 RecordedAt time.Time
 EffectiveUntil *time.Time
 Reason string
 ReviewReferences []string
}

// ProposeRestriction returns a detached, validated, negative-only revision.
// It never edits the supplied document or writes files. Restrictions are
// immediate at the explicit recorded time; older scheduled approvals cannot
// bypass the fresh-review rule in Evaluate.
func ProposeRestriction(s *registry.Store,d Document,o RestrictionOptions)(Document,RevisionReport,error){
 if o.Status!=Suspended&&o.Status!=Distrusted{return Document{},RevisionReport{},errors.New("only SUSPENDED or DISTRUSTED restrictions supported")}
 if !validTime(o.RecordedAt)||o.Status==Distrusted&&o.EffectiveUntil!=nil{return Document{},RevisionReport{},errors.New("explicit UTC time required; distrust must not expire")}
 index,err:=s.BuildIndex();if err!=nil{return Document{},RevisionReport{},err}
 raw,err:=DocumentBytes(d);if err!=nil{return Document{},RevisionReport{},err}
 next,err:=DecodeDocument(raw);if err!=nil{return Document{},RevisionReport{},err}
 v:=Decision{ID:o.ID,CertificateSHA256:o.CertificateSHA256,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:o.Status,RecordedAt:o.RecordedAt,EffectiveFrom:o.RecordedAt,Reason:o.Reason,EvidenceIDs:[]string{},ReviewReferences:append([]string{},o.ReviewReferences...)}
 if o.EffectiveUntil!=nil{t:=*o.EffectiveUntil;v.EffectiveUntil=&t}
 next.Decisions=append(next.Decisions,v)
 report,err:=CompareRevision(index,d,next);if err!=nil{return Document{},RevisionReport{},err}
 result,err:=next.Evaluate(s,o.RecordedAt,o.RecordedAt);if err!=nil{return Document{},RevisionReport{},err}
 for _,a:=range result.AnchorEvaluations{if a.FingerprintSHA256==o.CertificateSHA256&&a.Status==o.Status&&a.DecisionID==o.ID{return next,report,nil}}
 return Document{},RevisionReport{},errors.New("restriction did not take effect")
}
