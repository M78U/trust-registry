package review

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/M78U/trust-registry/pkg/sources"
 "github.com/emmansun/gmsm/smx509"
)

const MaxWorkspaceArchives=32

type ArchiveReference struct {
 ListingID string `json:"listingId"`
 SHA256 string `json:"sha256"`
}
type WorkspaceOptions struct {
 SnapshotSHA256 string
 EvidenceDir string
 ArchiveDir string
 Archives []ArchiveReference
 At time.Time
}
type WorkspaceArchive struct {
 Reference ArchiveReference `json:"reference"`
 MatchedProvenanceIDs []string `json:"matchedProvenanceIds"`
 Status string `json:"status"`
}
type WorkspaceProvenance struct {
 ID string `json:"id"`
 Record registry.ProvenanceRecord `json:"record"`
 ArchiveStatus string `json:"archiveStatus"`
 Archives []ArchiveReference `json:"archives"`
}
type WorkspaceCertificate struct {
 Certificate registry.CertificateRecord `json:"certificate"`
 ValidityStatus string `json:"validityStatus"`
 BasicConstraintsValid bool `json:"basicConstraintsValid"`
 KeyUsageBits int `json:"keyUsageBits"`
 ExtendedKeyUsageCodes []int `json:"extendedKeyUsageCodes"`
 UnknownExtendedKeyUsageOIDs []string `json:"unknownExtendedKeyUsageOids"`
 PolicyOIDs []string `json:"policyOids"`
 UnhandledCriticalExtensionOIDs []string `json:"unhandledCriticalExtensionOids"`
 PurposeAuthorization string `json:"purposeAuthorization"`
}
type WorkspaceSlot struct {
 Kind string `json:"kind"`
 SHA256 string `json:"sha256,omitempty"`
 Status string `json:"status"`
}
type WorkspaceTask struct {
 Requirement Requirement `json:"requirement"`
 DossierStatus string `json:"dossierStatus"`
 Slots []WorkspaceSlot `json:"slots"`
 Findings []string `json:"findings"`
 Status string `json:"status"`
}
type WorkspaceReport struct {
 SnapshotSHA256 string `json:"snapshotSHA256"`
 DossierSHA256 string `json:"dossierSHA256"`
 EvaluationTime time.Time `json:"evaluationTime"`
 Certificates []WorkspaceCertificate `json:"certificates"`
 Provenance []WorkspaceProvenance `json:"provenance"`
 Archives []WorkspaceArchive `json:"archives"`
 Tasks []WorkspaceTask `json:"tasks"`
 MissingArchiveRecords int `json:"missingArchiveRecords"`
 MissingOrInvalidSlots int `json:"missingOrInvalidSlots"`
 ArtifactFilesRead int `json:"artifactFilesRead"`
 ArtifactBytesRead int64 `json:"artifactBytesRead"`
 Status string `json:"status"`
 EvidenceConclusionStatus string `json:"evidenceConclusionStatus"`
 ReleaseAuthorized bool `json:"releaseAuthorized"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}

func workspaceDir(path string)error{
 if strings.TrimSpace(path)==""{return errors.New("explicit private directory required")}
 st,err:=os.Lstat(path);if err!=nil{return err}
 if !st.IsDir(){return errors.New("expected real private directory")}
 return nil
}

// Cache both failures and successes, charging actual reads (including bad
// hashes) against the same byte budget. Never enumerate the directory.
type workspaceArtifacts struct{
 dir string
 statuses map[string]string
 reads int
 total int64
}
func (a *workspaceArtifacts) inspect(h string)(string,error){
 if status,ok:=a.statuses[h];ok{return status,nil}
 if !hashPattern.MatchString(h){return "",errors.New("invalid evidence digest")}
 if len(a.statuses)>=MaxArtifacts{return "",errors.New("workspace distinct artifact limit")}
 status,err:=a.read(h)
 if err!=nil{return "",err}
 a.statuses[h]=status
 return status,nil
}
func(a *workspaceArtifacts)read(h string)(string,error){
 path:=filepath.Join(a.dir,h+".evidence")
 st,err:=os.Lstat(path)
 if os.IsNotExist(err){return "FILE_MISSING",nil}
 if err!=nil{return "FILE_UNREADABLE",nil}
 if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>MaxArtifactBytes{return "INVALID_FILE_TYPE_OR_SIZE",nil}
 // Reserve one extra byte for growth detection, never exceed total budget.
 remaining:=int64(MaxTotalArtifactBytes)-a.total
 if st.Size()>=remaining{return "",errors.New("workspace artifact byte budget")}
 f,err:=os.Open(path);if err!=nil{return "FILE_UNREADABLE",nil};defer f.Close()
 opened,err:=f.Stat();if err!=nil||!opened.Mode().IsRegular()||!os.SameFile(st,opened){return "FILE_CHANGED",nil}
 limit:=st.Size()+1
 raw,err:=io.ReadAll(io.LimitReader(f,limit))
 a.total+=int64(len(raw));a.reads++
 if err!=nil{return "FILE_UNREADABLE",nil}
 if int64(len(raw))!=st.Size(){return "FILE_CHANGED",nil}
 if digest(raw)!=h{return "HASH_MISMATCH",nil}
 return "BYTES_MATCHED_HUMAN_REVIEW_REQUIRED",nil
}

func technicalCertificate(raw []byte,at time.Time)(WorkspaceCertificate,error){
 record,der,err:=registry.ParseCertificate(raw);if err!=nil{return WorkspaceCertificate{},err}
 c,err:=smx509.ParseCertificate(der);if err!=nil{return WorkspaceCertificate{},err}
 v:=WorkspaceCertificate{Certificate:record,ValidityStatus:"WITHIN_VALIDITY",BasicConstraintsValid:c.BasicConstraintsValid,KeyUsageBits:int(c.KeyUsage),ExtendedKeyUsageCodes:[]int{},UnknownExtendedKeyUsageOIDs:[]string{},PolicyOIDs:[]string{},UnhandledCriticalExtensionOIDs:[]string{},PurposeAuthorization:"NOT_ESTABLISHED"}
 if record.NotAfter.Before(record.NotBefore){v.ValidityStatus="INVALID_VALIDITY_INTERVAL"}else if at.Before(record.NotBefore){v.ValidityStatus="NOT_YET_VALID"}else if at.After(record.NotAfter){v.ValidityStatus="EXPIRED"}
 for _,e:=range c.ExtKeyUsage{v.ExtendedKeyUsageCodes=append(v.ExtendedKeyUsageCodes,int(e))}
 for _,e:=range c.UnknownExtKeyUsage{v.UnknownExtendedKeyUsageOIDs=append(v.UnknownExtendedKeyUsageOIDs,e.String())}
 for _,e:=range c.PolicyIdentifiers{v.PolicyOIDs=append(v.PolicyOIDs,e.String())}
 for _,e:=range c.UnhandledCriticalExtensions{v.UnhandledCriticalExtensionOIDs=append(v.UnhandledCriticalExtensionOIDs,e.String())}
 return v,nil
}

type inspectArchiveFunc func(string,string,string)(sources.ArchiveReceipt,sources.AcquisitionReport,error)

// Workspace produces a private diagnostic report. It never mutates the
// dossier, fills review evidence automatically, or substitutes for Check.
func Workspace(raw []byte,d Dossier,o WorkspaceOptions)(WorkspaceReport,error){
 return workspace(raw,d,o,sources.InspectArchived)
}
func workspace(raw []byte,d Dossier,o WorkspaceOptions,inspect inspectArchiveFunc)(WorkspaceReport,error){
 if !validTime(o.At)||!hashPattern.MatchString(o.SnapshotSHA256)||len(raw)==0||len(raw)>snapshot.MaxEnvelopeBytes||digest(raw)!=o.SnapshotSHA256{return WorkspaceReport{},errors.New("exact independent snapshot pin and UTC evaluation time required")}
 tasks,sr,err:=requirements(raw);if err!=nil{return WorkspaceReport{},err}
 if o.At.Before(sr.Manifest.CreatedAt)||!o.At.Before(sr.Manifest.ExpiresAt){return WorkspaceReport{},errors.New("snapshot outside declared validity window")}
 if d.SchemaVersion!="1"||d.SnapshotSHA256!=sr.SnapshotSHA256||d.Reviews==nil||len(d.Reviews)!=len(tasks){return WorkspaceReport{},errors.New("dossier snapshot or membership mismatch")}
 db,err:=canonical(d);if err!=nil{return WorkspaceReport{},err}
 if _,err:=DecodeDossier(db);err!=nil{return WorkspaceReport{},err}
 if err:=workspaceDir(o.EvidenceDir);err!=nil{return WorkspaceReport{},err}
 if len(o.Archives)>MaxWorkspaceArchives||len(o.Archives)==0&&o.ArchiveDir!=""{return WorkspaceReport{},errors.New("explicit archive pins and directory must be provided together")}
 if len(o.Archives)>0{if err:=workspaceDir(o.ArchiveDir);err!=nil{return WorkspaceReport{},err}}
 result:=WorkspaceReport{SnapshotSHA256:sr.SnapshotSHA256,DossierSHA256:digest(db),EvaluationTime:o.At,Certificates:[]WorkspaceCertificate{},Provenance:[]WorkspaceProvenance{},Archives:[]WorkspaceArchive{},Tasks:[]WorkspaceTask{},Status:"HUMAN_REVIEW_REQUIRED",EvidenceConclusionStatus:"NOT_ESTABLISHED",TrustStatus:"NOT_ESTABLISHED"}
 rows:=map[string]Attestation{}
 for _,v:=range d.Reviews{if _,ok:=rows[v.Requirement.ID];ok{return WorkspaceReport{},errors.New("duplicate dossier task")};rows[v.Requirement.ID]=v}
 for _,t:=range tasks{v,ok:=rows[t.ID];if !ok||v.Requirement!=t{return WorkspaceReport{},errors.New("unknown, missing or altered dossier requirement")}}
 var env snapshot.Envelope
 if err:=json.Unmarshal(raw,&env);err!=nil{return WorkspaceReport{},err}
 // Full provenance-record equality, not just certificate fingerprint.
 byRecord:=map[string][]int{}
 for _,f:=range env.Payload{
  switch{
  case strings.HasPrefix(f.Path,"certificates/")&&strings.HasSuffix(f.Path,".der"):
   c,err:=technicalCertificate(f.Data,o.At);if err!=nil{return WorkspaceReport{},err}
   result.Certificates=append(result.Certificates,c)
  case strings.HasPrefix(f.Path,"provenance/"):
   var v registry.ProvenanceRecord
   if err:=json.Unmarshal(f.Data,&v);err!=nil{return WorkspaceReport{},err}
   key,err:=json.Marshal(v);if err!=nil{return WorkspaceReport{},err}
   byRecord[string(key)]=append(byRecord[string(key)],len(result.Provenance))
   result.Provenance=append(result.Provenance,WorkspaceProvenance{ID:digest(f.Data),Record:v,ArchiveStatus:"NO_MATCHING_PINNED_ACQUISITION_ARCHIVE",Archives:[]ArchiveReference{}})
  }
 }
 refs:=append([]ArchiveReference{},o.Archives...)
 sort.Slice(refs,func(i,j int)bool{return refs[i].ListingID<refs[j].ListingID})
 last:=""
 for _,ref:=range refs{
  if ref.ListingID==""||ref.ListingID==last||!hashPattern.MatchString(ref.SHA256){return WorkspaceReport{},errors.New("invalid or duplicate archive selection")}
  last=ref.ListingID
  receipt,a,err:=inspect(o.ArchiveDir,ref.ListingID,ref.SHA256)
  if err!=nil{return WorkspaceReport{},fmt.Errorf("archive %s: %w",ref.ListingID,err)}
  if !receipt.PinMatched||receipt.ArchiveSHA256!=ref.SHA256||receipt.ListingID!=ref.ListingID||a.Endpoint.ListingID!=ref.ListingID||receipt.CertificateSHA256!=a.Preview.Provenance.CertificateSHA256||receipt.SourceFileSHA256!=a.Preview.Provenance.SourceFileSHA256||!receipt.RecordedAt.Equal(a.Preview.Provenance.RecordedAt){return WorkspaceReport{},errors.New("archive receipt identity mismatch")}
  key,err:=json.Marshal(a.Preview.Provenance);if err!=nil{return WorkspaceReport{},err}
  link:=WorkspaceArchive{Reference:ref,Status:"NOT_IN_SNAPSHOT",MatchedProvenanceIDs:[]string{}}
  for _,i:=range byRecord[string(key)]{
   v:=&result.Provenance[i];v.ArchiveStatus="PINNED_OBSERVATION_BYTES_MATCHED";v.Archives=append(v.Archives,ref)
   link.MatchedProvenanceIDs=append(link.MatchedProvenanceIDs,v.ID)
   link.Status="MATCHED_SNAPSHOT_PROVENANCE"
  }
  result.Archives=append(result.Archives,link)
 }
 for _,v:=range result.Provenance{if len(v.Archives)==0{result.MissingArchiveRecords++}}
 av:=workspaceArtifacts{dir:o.EvidenceDir,statuses:map[string]string{}}
 identityReviewers:=map[string]map[string]bool{}
 for _,t:=range tasks{
  v:=rows[t.ID]
  if t.Kind=="SOURCE_IDENTITY"&&v.Status=="APPROVED"{
   if identityReviewers[t.CertificateSHA256]==nil{identityReviewers[t.CertificateSHA256]=map[string]bool{}}
   identityReviewers[t.CertificateSHA256][v.Reviewer]=true
  }
 }
 for _,t:=range tasks{
  v:=rows[t.ID]
  row:=WorkspaceTask{Requirement:t,DossierStatus:v.Status,Slots:[]WorkspaceSlot{},Findings:[]string{},Status:"HUMAN_REVIEW_REQUIRED"}
  kinds:=artifactKinds(t.Kind)
  expected:=map[string]bool{};for _,k:=range kinds{expected[k]=true}
  supplied:=map[string][]Artifact{}
  used:=map[string]bool{}
  for _,a:=range v.Evidence{
   if !expected[a.Kind]{row.Findings=append(row.Findings,"UNEXPECTED_EVIDENCE_KIND");continue}
   if used[a.SHA256]{row.Findings=append(row.Findings,"DUPLICATE_EVIDENCE_DIGEST")}
   used[a.SHA256]=true;supplied[a.Kind]=append(supplied[a.Kind],a)
  }
  for _,k:=range kinds{
   slot:=WorkspaceSlot{Kind:k,Status:"NOT_REFERENCED"}
   candidates:=supplied[k]
   if len(candidates)>1{slot.Status="DUPLICATE_KIND"}else if len(candidates)==1{
    a:=candidates[0];slot.SHA256=a.SHA256
    if !validText(a.Reference,1024){slot.Status="INVALID_REFERENCE"}else{
     status,err:=av.inspect(a.SHA256);if err!=nil{return WorkspaceReport{},err};slot.Status=status
    }
   }
   if slot.Status!="BYTES_MATCHED_HUMAN_REVIEW_REQUIRED"{result.MissingOrInvalidSlots++}
   row.Slots=append(row.Slots,slot)
  }
  if v.Status=="APPROVED"{
   if !reviewerPattern.MatchString(v.Reviewer)||v.ReviewedAt==nil||!validTime(*v.ReviewedAt)||v.ReviewedAt.Before(sr.Manifest.CreatedAt)||v.ReviewedAt.After(o.At)||!validText(v.Note,2048){row.Findings=append(row.Findings,"INVALID_APPROVAL_METADATA")}
   if (t.Kind=="REDISTRIBUTION"||t.Kind=="POLICY_SCOPE")&&identityReviewers[t.CertificateSHA256][v.Reviewer]{row.Findings=append(row.Findings,"SEPARATE_REVIEWER_REQUIRED")}
   for j,k:=range kinds{if j>=len(v.Evidence)||v.Evidence[j].Kind!=k{row.Findings=append(row.Findings,"APPROVED_EVIDENCE_ORDER_MISMATCH");break}}
  }
  result.Tasks=append(result.Tasks,row)
 }
 result.ArtifactFilesRead=av.reads
 result.ArtifactBytesRead=av.total
 return result,nil
}

// EvidenceArtifact stages exact private evidence bytes under a digest name.
// It does not create a dossier reference or make any assertion of meaning.
func EvidenceArtifact(dir string,raw []byte)(string,error){
 if err:=workspaceDir(dir);err!=nil{return "",err}
 if len(raw)==0||len(raw)>MaxArtifactBytes{return "",errors.New("evidence size limit")}
 h:=digest(raw);path:=filepath.Join(dir,h+".evidence")
 verifyExisting:=func()error{
  a:=workspaceArtifacts{dir:dir,statuses:map[string]string{}}
  status,err:=a.inspect(h);if err!=nil{return err}
  if status!="BYTES_MATCHED_HUMAN_REVIEW_REQUIRED"{return errors.New("existing evidence path invalid or changed")}
  return nil
 }
 if _,err:=os.Lstat(path);err==nil{return h,verifyExisting()}else if !os.IsNotExist(err){return "",err}
 f,err:=os.CreateTemp(dir,".pending-");if err!=nil{return "",err};defer os.Remove(f.Name())
 if _,err=f.Write(raw);err==nil{err=f.Sync()};closeErr:=f.Close();if err==nil{err=closeErr};if err!=nil{return "",err}
 if err:=os.Link(f.Name(),path);err!=nil{if os.IsExist(err){return h,verifyExisting()};return "",err}
 return h,nil
}
