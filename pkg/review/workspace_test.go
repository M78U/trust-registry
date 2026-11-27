package review

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/M78U/trust-registry/pkg/sources"
)

func TestWorkspaceDiagnosticAndArtifactDeduplication(t *testing.T){
 raw,at:=reviewFixture(t)
 d,err:=Plan(raw);if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 o:=WorkspaceOptions{SnapshotSHA256:digest(raw),EvidenceDir:dir,At:at}
 initial,err:=Workspace(raw,d,o)
 if err!=nil||len(initial.Certificates)!=1||len(initial.Provenance)!=2||len(initial.Tasks)!=6||initial.MissingArchiveRecords!=2||initial.MissingOrInvalidSlots!=8||initial.ReleaseAuthorized||initial.ReleaseAuthenticated{t.Fatal(initial,err)}
 if initial.Certificates[0].PurposeAuthorization!="NOT_ESTABLISHED"||!initial.Certificates[0].BasicConstraintsValid{t.Fatal(initial.Certificates)}
 payload:=[]byte("synthetic source observation")
 h,err:=EvidenceArtifact(dir,payload);if err!=nil{t.Fatal(err)}
 h2,err:=EvidenceArtifact(dir,payload);if err!=nil||h2!=h{t.Fatal(h2,err)}
 for i:=range d.Reviews{if d.Reviews[i].Requirement.Kind=="SOURCE_IDENTITY"{d.Reviews[i].Evidence=[]Artifact{{"ISSUER_SOURCE",h,"local observation"}}}}
 report,err:=Workspace(raw,d,o)
 if err!=nil||report.ArtifactFilesRead!=1||report.ArtifactBytesRead!=int64(len(payload))||report.MissingOrInvalidSlots!=6||report.Status!="HUMAN_REVIEW_REQUIRED"{t.Fatal(report,err)}
 if _,err:=Check(raw,d,dir,at);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,h+".evidence"),[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
 report,err=Workspace(raw,d,o)
 if err!=nil||report.ArtifactFilesRead!=1||report.MissingOrInvalidSlots!=8{t.Fatal(report,err)}
 if _,err:=EvidenceArtifact(dir,payload);err==nil{t.Fatal("tampered existing evidence overwritten")}
 o.SnapshotSHA256=strings.Repeat("0",64)
 if _,err:=Workspace(raw,d,o);err==nil{t.Fatal("wrong snapshot pin")}
}
func TestWorkspaceExactProvenanceAssociation(t *testing.T){
 raw,at:=reviewFixture(t);d,err:=Plan(raw);if err!=nil{t.Fatal(err)}
 var env snapshot.Envelope
 if err:=json.Unmarshal(raw,&env);err!=nil{t.Fatal(err)}
 var prov registry.ProvenanceRecord
 for _,f:=range env.Payload{if strings.HasPrefix(f.Path,"provenance/"){if err:=json.Unmarshal(f.Data,&prov);err!=nil{t.Fatal(err)};break}}
 pin:=strings.Repeat("a",64)
 o:=WorkspaceOptions{SnapshotSHA256:digest(raw),EvidenceDir:t.TempDir(),ArchiveDir:t.TempDir(),Archives:[]ArchiveReference{{"synthetic",pin}},At:at}
 calls:=0
 fixture:=func(_ string,id,h string)(sources.ArchiveReceipt,sources.AcquisitionReport,error){
  calls++
  receipt:=sources.ArchiveReceipt{ListingID:id,ArchiveSHA256:h,SourceFileSHA256:prov.SourceFileSHA256,CertificateSHA256:prov.CertificateSHA256,RecordedAt:prov.RecordedAt,PinMatched:true}
  a:=sources.AcquisitionReport{Endpoint:sources.Endpoint{ListingID:id},Preview:sources.IntakePreview{Provenance:prov}}
  return receipt,a,nil
 }
 report,err:=workspace(raw,d,o,fixture)
 if err!=nil||calls!=1||report.MissingArchiveRecords!=1||len(report.Archives[0].MatchedProvenanceIDs)!=1||report.MissingOrInvalidSlots!=8{t.Fatal(report,err)}
 // Same certificate and source bytes, different observation time: no match.
 prov.RecordedAt=prov.RecordedAt.Add(-time.Second)
 report,err=workspace(raw,d,o,fixture)
 if err!=nil||report.MissingArchiveRecords!=2||report.Archives[0].Status!="NOT_IN_SNAPSHOT"{t.Fatal(report,err)}
 o.Archives=append(o.Archives,o.Archives[0])
 if _,err:=workspace(raw,d,o,fixture);err==nil{t.Fatal("duplicate archive pin")}
}
