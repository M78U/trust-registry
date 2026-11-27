package review

import(
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/snapshot"
)
func TestReuseEvidenceResetsEveryDecision(t *testing.T){
 raw,at:=reviewFixture(t)
 old,err:=Plan(raw);if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 h,err:=EvidenceArtifact(dir,[]byte("source fixture"));if err!=nil{t.Fatal(err)}
 for i:=range old.Reviews{
  v:=&old.Reviews[i]
  if v.Requirement.Kind=="SOURCE_IDENTITY"{v.Evidence=[]Artifact{{"ISSUER_SOURCE",h,"fixture"}};v.Status="APPROVED";v.Reviewer="old-reviewer";v.ReviewedAt=&at;v.Note="old decision"}
 }
 var env snapshot.Envelope
 if err:=json.Unmarshal(raw,&env);err!=nil{t.Fatal(err)}
 env.Manifest.Sequence++
 later:=at.Add(time.Minute);env.Manifest.CreatedAt=later
 next,err:=json.Marshal(env);if err!=nil{t.Fatal(err)};next=append(next,'\n')
 ob,err:=DossierBytes(old);if err!=nil{t.Fatal(err)}
 o:=ReuseOptions{PreviousSnapshotSHA256:digest(raw),PreviousDossierSHA256:digest(ob),NextSnapshotSHA256:digest(next),EvidenceDir:dir,At:later}
 d,r,err:=ReuseEvidence(raw,next,old,o)
 if err!=nil||r.ReusedReferences!=2||r.TasksWithReuse!=2||r.ArtifactFilesRead!=1||r.NewOrChangedTasks!=0||r.ReleaseAuthorized||r.ReleaseAuthenticated{t.Fatal(r,err)}
 for _,v:=range d.Reviews{if v.Status!="PENDING"||v.Reviewer!=""||v.ReviewedAt!=nil||v.Note!=""{t.Fatal("old decision transferred",v)}}
 gate,err:=Check(next,d,dir,later);if err!=nil||gate.Status!="BLOCKED"{t.Fatal(gate,err)}
 report,err:=Workspace(next,d,WorkspaceOptions{SnapshotSHA256:digest(next),EvidenceDir:dir,At:later})
 if err!=nil||report.Progress.Pending!=6||report.Progress.QueueCount!=6||len(report.ReviewQueue)!=6{t.Fatal(report.Progress,err)}
 if err:=os.WriteFile(filepath.Join(dir,h+".evidence"),[]byte("modified"),0600);err!=nil{t.Fatal(err)}
 _,r,err=ReuseEvidence(raw,next,old,o);if err!=nil||r.ReusedReferences!=0||r.ArtifactFilesRead!=1{t.Fatal(r,err)}
 o.PreviousDossierSHA256=strings.Repeat("0",64)
 if _,_,err:=ReuseEvidence(raw,next,old,o);err==nil{t.Fatal("incorrect dossier pin")}
}
