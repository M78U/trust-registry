package review

import (
 "errors"
 "time"

 "github.com/M78U/trust-registry/pkg/snapshot"
)

// Progress is a local diagnostic count, not authenticated approval.
type WorkspaceProgress struct{
 Total int `json:"total"`
 Pending int `json:"pending"`
 Rejected int `json:"rejected"`
 AssertedApproved int `json:"assertedApproved"`
 EvidenceComplete int `json:"evidenceComplete"`
 EvidenceIncomplete int `json:"evidenceIncomplete"`
 AssertedApprovalComplete int `json:"assertedApprovalComplete"`
 QueueCount int `json:"queueCount"`
}
type QueueItem struct{
 RequirementID string `json:"requirementId"`
 Kind string `json:"kind"`
 CertificateSHA256 string `json:"certificateSHA256"`
 Reason string `json:"reason"`
 MissingKinds []string `json:"missingKinds"`
}
func workspaceProgress(tasks []WorkspaceTask)(WorkspaceProgress,[]QueueItem){
 p:=WorkspaceProgress{Total:len(tasks)}
 q:=[]QueueItem{}
 for _,t:=range tasks{
  missing:=[]string{}
  for _,s:=range t.Slots{if s.Status!="BYTES_MATCHED_HUMAN_REVIEW_REQUIRED"{missing=append(missing,s.Kind)}}
  if len(missing)==0&&len(t.Findings)==0{p.EvidenceComplete++}else{p.EvidenceIncomplete++}
  reason:=""
  switch t.DossierStatus{
  case "PENDING":p.Pending++;reason="PENDING_HUMAN_REVIEW"
  case "REJECTED":p.Rejected++;reason="REJECTED_REQUIRES_RESOLUTION"
  case "APPROVED":
   p.AssertedApproved++
   if len(missing)==0&&len(t.Findings)==0{p.AssertedApprovalComplete++}else{reason="ASSERTED_APPROVAL_HAS_FINDINGS"}
  }
  if reason!=""{q=append(q,QueueItem{t.Requirement.ID,t.Requirement.Kind,t.Requirement.CertificateSHA256,reason,missing})}
 }
 p.QueueCount=len(q)
 return p,q
}

type ReuseOptions struct{
 PreviousSnapshotSHA256 string
 PreviousDossierSHA256 string
 NextSnapshotSHA256 string
 EvidenceDir string
 At time.Time
}
type ReuseItem struct{
 RequirementID string `json:"requirementId"`
 Status string `json:"status"`
 ReusedKinds []string `json:"reusedKinds"`
}
type ReuseReport struct{
 PreviousSnapshotSHA256 string `json:"previousSnapshotSHA256"`
 PreviousDossierSHA256 string `json:"previousDossierSHA256"`
 NextSnapshotSHA256 string `json:"nextSnapshotSHA256"`
 NextDossierSHA256 string `json:"nextDossierSHA256"`
 ReusedReferences int `json:"reusedReferences"`
 TasksWithReuse int `json:"tasksWithReuse"`
 NewOrChangedTasks int `json:"newOrChangedTasks"`
 RemovedTasks int `json:"removedTasks"`
 ArtifactFilesRead int `json:"artifactFilesRead"`
 Items []ReuseItem `json:"items"`
 Status string `json:"status"`
 ReleaseAuthorized bool `json:"releaseAuthorized"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}

// ReuseEvidence creates a NEW pending dossier. Only exact identical
// requirements can reuse verified byte references. No old review metadata,
// rejection, approval, or signature is transferred. This is not a
// publication-transition check or a release gate.
func ReuseEvidence(previous,next []byte,old Dossier,o ReuseOptions)(Dossier,ReuseReport,error){
 fail:=func(e error)(Dossier,ReuseReport,error){return Dossier{},ReuseReport{},e}
 if !validTime(o.At)||len(previous)==0||len(previous)>snapshot.MaxEnvelopeBytes||len(next)==0||len(next)>snapshot.MaxEnvelopeBytes||!hashPattern.MatchString(o.PreviousSnapshotSHA256)||!hashPattern.MatchString(o.NextSnapshotSHA256)||!hashPattern.MatchString(o.PreviousDossierSHA256)||digest(previous)!=o.PreviousSnapshotSHA256||digest(next)!=o.NextSnapshotSHA256{return fail(errors.New("independent snapshot and canonical dossier pins required"))}
 if err:=workspaceDir(o.EvidenceDir);err!=nil{return fail(err)}
 before,pr,err:=requirements(previous);if err!=nil{return fail(err)}
 after,nr,err:=requirements(next);if err!=nil{return fail(err)}
 if nr.Manifest.Sequence<=pr.Manifest.Sequence||!nr.Manifest.CreatedAt.After(pr.Manifest.CreatedAt)||o.At.Before(nr.Manifest.CreatedAt)||!o.At.Before(nr.Manifest.ExpiresAt){return fail(errors.New("next snapshot must be newer and currently valid"))}
 if old.SchemaVersion!="1"||old.SnapshotSHA256!=pr.SnapshotSHA256||old.Reviews==nil||len(old.Reviews)!=len(before){return fail(errors.New("previous dossier identity mismatch"))}
 ob,err:=canonical(old);if err!=nil{return fail(err)}
 if digest(ob)!=o.PreviousDossierSHA256{return fail(errors.New("previous canonical dossier pin mismatch"))}
 if _,err:=DecodeDossier(ob);err!=nil{return fail(err)}
 oldRows:=map[string]Attestation{}
 for _,v:=range old.Reviews{if _,ok:=oldRows[v.Requirement.ID];ok{return fail(errors.New("duplicate previous task"))};oldRows[v.Requirement.ID]=v}
 for _,t:=range before{v,ok:=oldRows[t.ID];if !ok||v.Requirement!=t{return fail(errors.New("altered previous task"))}}
 d:=Dossier{SchemaVersion:"1",SnapshotSHA256:nr.SnapshotSHA256,Reviews:[]Attestation{}}
 report:=ReuseReport{PreviousSnapshotSHA256:pr.SnapshotSHA256,PreviousDossierSHA256:o.PreviousDossierSHA256,NextSnapshotSHA256:nr.SnapshotSHA256,Items:[]ReuseItem{},Status:"PENDING_DOSSIER_WITH_RECHECKED_REFERENCES",TrustStatus:"NOT_ESTABLISHED"}
 av:=workspaceArtifacts{dir:o.EvidenceDir,statuses:map[string]string{}}
 retained:=map[string]bool{}
 for _,t:=range after{
  row:=Attestation{Requirement:t,Status:"PENDING",Evidence:[]Artifact{}}
  item:=ReuseItem{RequirementID:t.ID,Status:"NEW_OR_CHANGED_REQUIREMENT",ReusedKinds:[]string{}}
  prior,ok:=oldRows[t.ID]
  if !ok||prior.Requirement!=t{report.NewOrChangedTasks++}else{
   retained[t.ID]=true
   item.Status="NO_REUSABLE_REFERENCES"
   if prior.Status=="REJECTED"{item.Status="PREVIOUS_REJECTION_NOT_REUSED"}else{
    kinds:=artifactKinds(t.Kind)
    allowed:=map[string]bool{};for _,k:=range kinds{allowed[k]=true}
    refs:=map[string]Artifact{}
    used:=map[string]bool{}
    invalid:=false
    for _,a:=range prior.Evidence{
     if !allowed[a.Kind]||used[a.SHA256]||refs[a.Kind].Kind!=""||!validText(a.Reference,1024){invalid=true;break}
     refs[a.Kind]=a;used[a.SHA256]=true
    }
    if invalid{item.Status="PREVIOUS_REFERENCES_INVALID"}else{
     for _,k:=range kinds{
      a,ok:=refs[k];if !ok{continue}
      state,err:=av.inspect(a.SHA256);if err!=nil{return fail(err)}
      if state!="BYTES_MATCHED_HUMAN_REVIEW_REQUIRED"{continue}
      row.Evidence=append(row.Evidence,a);item.ReusedKinds=append(item.ReusedKinds,k);report.ReusedReferences++
     }
     if len(row.Evidence)>0{report.TasksWithReuse++;item.Status="REFERENCES_RECHECKED_REVIEW_REQUIRED"}
    }
   }
  }
  d.Reviews=append(d.Reviews,row);report.Items=append(report.Items,item)
 }
 report.RemovedTasks=len(before)-len(retained)
 nb,err:=canonical(d);if err!=nil{return fail(err)}
 if _,err:=DecodeDossier(nb);err!=nil{return fail(err)}
 report.NextDossierSHA256=digest(nb);report.ArtifactFilesRead=av.reads
 return d,report,nil
}

// DossierBytes exposes the canonical local representation used for pins.
func DossierBytes(d Dossier)([]byte,error){return canonical(d)}
