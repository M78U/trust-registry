// Package review creates and checks local release-candidate review dossiers.
// Passing this gate is not reviewer authentication or release authorization.
package review

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strings"
 "time"
 "unicode"
 "unicode/utf8"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/M78U/trust-registry/schemas"
)

const MaxTasks=2048
const MaxDossierBytes=schemas.MaxJSONBytes
const MaxArtifactBytes=4<<20
const MaxArtifacts=1024
const MaxTotalArtifactBytes=64<<20
var hashPattern=regexp.MustCompile(`^[a-f0-9]{64}$`)
var reviewerPattern=regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Requirement struct{
 ID string `json:"id"`
 Kind string `json:"kind"`
 CertificateSHA256 string `json:"certificateSHA256"`
 ProvenanceID string `json:"provenanceId"`
 PolicySHA256 string `json:"policySHA256"`
 PolicyID string `json:"policyId"`
 PolicyVersion int `json:"policyVersion"`
 Purpose string `json:"purpose"`
 Role string `json:"role"`
}
type Artifact struct{
 Kind string `json:"kind"`
 SHA256 string `json:"sha256"`
 Reference string `json:"reference"`
}
type Attestation struct{
 Requirement Requirement `json:"requirement"`
 Status string `json:"status"`
 Reviewer string `json:"reviewer"`
 ReviewedAt *time.Time `json:"reviewedAt"`
 Evidence []Artifact `json:"evidence"`
 Note string `json:"note"`
}
type Dossier struct{
 SchemaVersion string `json:"schemaVersion"`
 SnapshotSHA256 string `json:"snapshotSHA256"`
 Reviews []Attestation `json:"reviews"`
}
type Finding struct{
 RequirementID string `json:"requirementId"`
 Reason string `json:"reason"`
}
type Report struct{
 SnapshotSHA256 string `json:"snapshotSHA256"`
 DossierSHA256 string `json:"dossierSHA256"`
 Sequence uint64 `json:"sequence"`
 EvaluationTime time.Time `json:"evaluationTime"`
 Required int `json:"required"`
 Approved int `json:"approved"`
 VerifiedArtifactFiles int `json:"verifiedArtifactFiles"`
 Findings []Finding `json:"findings"`
 Status string `json:"status"`
 ReviewerAuthentication string `json:"reviewerAuthentication"`
 EvidenceConclusionStatus string `json:"evidenceConclusionStatus"`
 ReleaseAuthorized bool `json:"releaseAuthorized"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}
func digest(raw []byte)string{h:=sha256.Sum256(raw);return hex.EncodeToString(h[:])}
func validTime(t time.Time)bool{return !t.IsZero()&&t.Location()==time.UTC&&t.Year()>=1&&t.Year()<=9999}
func validText(s string,n int)bool{return strings.TrimSpace(s)!=""&&len(s)<=n&&utf8.ValidString(s)&&strings.IndexFunc(s,unicode.IsControl)<0}
func canonical(v Dossier)([]byte,error){b,err:=json.Marshal(v);if err!=nil{return nil,err};b=append(b,'\n');if len(b)>MaxDossierBytes{return nil,errors.New("dossier size limit")};return b,nil}
func DecodeDossier(raw []byte)(Dossier,error){
 if err:=schemas.ValidateJSON(schemas.ReleaseReview,raw);err!=nil{return Dossier{},err}
 var d Dossier
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 if err:=dec.Decode(&d);err!=nil{return Dossier{},err}
 return d,nil
}
func requirements(raw []byte)([]Requirement,snapshot.Report,error){
 verified,err:=snapshot.Verify(raw,"");if err!=nil{return nil,snapshot.Report{},err}
 var env snapshot.Envelope
 if err:=json.Unmarshal(raw,&env);err!=nil{return nil,snapshot.Report{},err}
 tasks:=[]Requirement{}
 add:=func(t Requirement)error{
  if len(tasks)>=MaxTasks{return errors.New("review task limit exceeded")}
  tasks=append(tasks,t);return nil
 }
 for _,f:=range env.Payload{
  if strings.HasPrefix(f.Path,"provenance/"){
   var prov registry.ProvenanceRecord
   if err:=json.Unmarshal(f.Data,&prov);err!=nil{return nil,snapshot.Report{},err}
   if prov.RecordedAt.After(env.Manifest.CreatedAt){return nil,snapshot.Report{},errors.New("snapshot contains future-recorded provenance")}
   id:=digest(f.Data)
   for _,kind:=range []string{"SOURCE_IDENTITY","REDISTRIBUTION"}{
    if err:=add(Requirement{ID:kind+":"+id,Kind:kind,CertificateSHA256:prov.CertificateSHA256,ProvenanceID:id});err!=nil{return nil,snapshot.Report{},err}
   }
  }else if strings.HasPrefix(f.Path,"policies/"){
   d,err:=policy.DecodeDocument(f.Data);if err!=nil{return nil,snapshot.Report{},err}
   for _,v:=range d.Reviews{if v.RecordedAt.After(env.Manifest.CreatedAt){return nil,snapshot.Report{},errors.New("snapshot contains future-recorded policy review")}}
   for _,v:=range d.Decisions{if v.RecordedAt.After(env.Manifest.CreatedAt){return nil,snapshot.Report{},errors.New("snapshot contains future-recorded policy decision")}}
   h:=digest(f.Data);p:=d.Policy
   base:=Requirement{ID:"POLICY_DISCLOSURE:"+h,Kind:"POLICY_DISCLOSURE",PolicySHA256:h,PolicyID:p.ID,PolicyVersion:p.Version,Purpose:p.Purpose}
   if err:=add(base);err!=nil{return nil,snapshot.Report{},err}
   for _,group:=range []struct{role string;fps []string}{{"TRUST_ANCHOR",p.TrustAnchors},{"INTERMEDIATE_CANDIDATE",p.IntermediateCandidates}}{
    for _,fp:=range group.fps{
     t:=base;t.ID="POLICY_SCOPE:"+h+":"+group.role+":"+fp;t.Kind="POLICY_SCOPE";t.Role=group.role;t.CertificateSHA256=fp
     if err:=add(t);err!=nil{return nil,snapshot.Report{},err}
    }
   }
  }
 }
 sort.Slice(tasks,func(i,j int)bool{return tasks[i].ID<tasks[j].ID})
 return tasks,verified,nil
}

// Plan emits a complete editable dossier with no default approval.
func Plan(raw []byte)(Dossier,error){
 tasks,r,err:=requirements(raw);if err!=nil{return Dossier{},err}
 d:=Dossier{SchemaVersion:"1",SnapshotSHA256:r.SnapshotSHA256,Reviews:[]Attestation{}}
 for _,t:=range tasks{d.Reviews=append(d.Reviews,Attestation{Requirement:t,Status:"PENDING",Evidence:[]Artifact{}})}
 if _,err:=canonical(d);err!=nil{return Dossier{},err}
 return d,nil
}
func artifactKinds(kind string)[]string{
 switch kind{
 case "SOURCE_IDENTITY":return []string{"ISSUER_SOURCE","INDEPENDENT_FINGERPRINT"}
 case "REDISTRIBUTION":return []string{"REDISTRIBUTION_TERMS"}
 case "POLICY_SCOPE":return []string{"PURPOSE_AUTHORIZATION"}
 case "POLICY_DISCLOSURE":return []string{"DISCLOSURE_REVIEW"}
 default:return nil
 }
}
type artifactVerifier struct{dir string;checked map[string]bool;total int}
func(a *artifactVerifier)check(h string)error{
 if !hashPattern.MatchString(h){return errors.New("invalid artifact digest")}
 if a.checked[h]{return nil}
 if len(a.checked)>=MaxArtifacts{return errors.New("artifact count limit")}
 path:=filepath.Join(a.dir,h+".evidence")
 i,err:=os.Lstat(path);if err!=nil{return err}
 if !i.Mode().IsRegular()||i.Size()<=0||i.Size()>MaxArtifactBytes||i.Size()>int64(MaxTotalArtifactBytes-a.total){return errors.New("artifact type/size limit")}
 f,err:=os.Open(path);if err!=nil{return err};defer f.Close()
 st,err:=f.Stat();if err!=nil{return err}
 if !st.Mode().IsRegular()||!os.SameFile(i,st){return errors.New("artifact changed while opening")}
 raw,err:=io.ReadAll(io.LimitReader(f,MaxArtifactBytes+1));if err!=nil{return err}
 if len(raw)==0||len(raw)>MaxArtifactBytes||len(raw)>MaxTotalArtifactBytes-a.total||digest(raw)!=h{return errors.New("artifact content address or budget mismatch")}
 a.checked[h]=true;a.total+=len(raw);return nil
}

// Check binds every local assertion and artifact to exact snapshot membership.
// The filesystem, review dossier and clock are operator-controlled inputs.
// Matching hashes prove only byte identity, not the truth of evidence.
func Check(raw []byte,d Dossier,evidenceDir string,at time.Time)(Report,error){
 if !validTime(at){return Report{},errors.New("explicit UTC gate time required")}
 tasks,sr,err:=requirements(raw);if err!=nil{return Report{},err}
 if at.Before(sr.Manifest.CreatedAt)||!at.Before(sr.Manifest.ExpiresAt){return Report{},errors.New("snapshot outside declared validity window")}
 if d.SchemaVersion!="1"||d.SnapshotSHA256!=sr.SnapshotSHA256||d.Reviews==nil||len(d.Reviews)!=len(tasks){return Report{},errors.New("dossier snapshot identity or task membership mismatch")}
 doc,err:=canonical(d);if err!=nil{return Report{},err}
 if _,err:=DecodeDossier(doc);err!=nil{return Report{},err}
 if strings.TrimSpace(evidenceDir)==""{return Report{},errors.New("private evidence directory required")}
 dir,err:=filepath.Abs(evidenceDir);if err!=nil{return Report{},err}
 i,err:=os.Lstat(dir);if err!=nil{return Report{},err}
 if !i.IsDir(){return Report{},errors.New("expected regular private evidence directory")}
 av:=artifactVerifier{dir:dir,checked:map[string]bool{}}
 result:=Report{SnapshotSHA256:sr.SnapshotSHA256,DossierSHA256:digest(doc),Sequence:sr.Manifest.Sequence,EvaluationTime:at,Required:len(tasks),Findings:[]Finding{},Status:"BLOCKED",ReviewerAuthentication:"NOT_ESTABLISHED",EvidenceConclusionStatus:"HUMAN_REVIEW_REQUIRED",TrustStatus:"NOT_ESTABLISHED"}
 rows:=map[string]Attestation{}
 for _,v:=range d.Reviews{
  if _,ok:=rows[v.Requirement.ID];ok{return Report{},errors.New("duplicate review task")}
  rows[v.Requirement.ID]=v
 }
 identityReviewers:=map[string]map[string]bool{}
 approved:=[]Attestation{}
 for _,t:=range tasks{
  v,ok:=rows[t.ID];if !ok||v.Requirement!=t{return Report{},errors.New("unknown, missing or altered review requirement")}
  switch v.Status{
  case "PENDING","REJECTED":
   result.Findings=append(result.Findings,Finding{t.ID,v.Status})
   continue
  case "APPROVED":
  default:return Report{},errors.New("unknown review status")
  }
  if !reviewerPattern.MatchString(v.Reviewer)||v.ReviewedAt==nil||!validTime(*v.ReviewedAt)||v.ReviewedAt.Before(sr.Manifest.CreatedAt)||v.ReviewedAt.After(at)||!validText(v.Note,2048){return Report{},fmt.Errorf("invalid approval metadata for %s",t.ID)}
  kinds:=artifactKinds(t.Kind)
  if len(v.Evidence)!=len(kinds){return Report{},fmt.Errorf("missing required evidence types for %s",t.ID)}
  used:=map[string]bool{}
  for j,k:=range kinds{
   a:=v.Evidence[j]
   if a.Kind!=k||used[a.SHA256]||!validText(a.Reference,1024){return Report{},fmt.Errorf("invalid evidence reference for %s",t.ID)}
   used[a.SHA256]=true
   if err:=av.check(a.SHA256);err!=nil{return Report{},fmt.Errorf("artifact for %s: %w",t.ID,err)}
  }
  if t.Kind=="SOURCE_IDENTITY"{
   if identityReviewers[t.CertificateSHA256]==nil{identityReviewers[t.CertificateSHA256]=map[string]bool{}}
   identityReviewers[t.CertificateSHA256][v.Reviewer]=true
  }
  approved=append(approved,v)
 }
 for _,v:=range approved{
  t:=v.Requirement
  if (t.Kind=="REDISTRIBUTION"||t.Kind=="POLICY_SCOPE")&&identityReviewers[t.CertificateSHA256][v.Reviewer]{
   result.Findings=append(result.Findings,Finding{t.ID,"SEPARATE_REVIEWER_REQUIRED"});continue
  }
  result.Approved++
 }
 if sr.Validation.Certificates==0{result.Findings=append(result.Findings,Finding{"SNAPSHOT","EMPTY_CA_INVENTORY"})}
 result.VerifiedArtifactFiles=len(av.checked)
 sort.Slice(result.Findings,func(i,j int)bool{return result.Findings[i].RequirementID<result.Findings[j].RequirementID})
 if len(result.Findings)==0&&result.Approved==result.Required{result.Status="LOCAL_REVIEW_REQUIREMENTS_SATISFIED"}
 return result,nil
}
