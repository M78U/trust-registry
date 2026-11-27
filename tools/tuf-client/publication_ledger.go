package tufclient

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/snapshot"
)

const MaxPublicationRecords=128
const MaxPublicationLedgerBytes=256<<20
const maxPublicationRecordBytes=maxEvidenceBytes+65536

type publicationRecord struct{
 SchemaVersion string `json:"schemaVersion"`
 PreviousRecordSHA256 string `json:"previousRecordSHA256"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 ApprovalSHA256 string `json:"approvalSHA256"`
 DossierSHA256 string `json:"dossierSHA256"`
 Evidence evidence `json:"evidence"`
}
type LedgerReceipt struct{
 Sequence uint64 `json:"sequence"`
 RecordSHA256 string `json:"recordSHA256"`
 PreviousRecordSHA256 string `json:"previousRecordSHA256"`
 SnapshotSHA256 string `json:"snapshotSHA256"`
 RootSHA256 string `json:"rootSHA256"`
 InitialRootSHA256 string `json:"initialRootSHA256"`
 RootVersion int `json:"rootVersion"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 ApprovalSHA256 string `json:"approvalSHA256"`
 DossierSHA256 string `json:"dossierSHA256"`
 BuiltAt time.Time `json:"builtAt"`
 Records int `json:"records"`
 Status string `json:"status"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}
type LedgerOptions struct{
 Directory string
 AuthoritySHA256 string
 ExpectedHeadSHA256 string // optional independently retained record pin
 Reviewed ReviewedPublishOptions
 // Optional explicit complete chain for a rotated ledger. Initial pin stays fixed.
 RootChain [][]byte
 InitialRootSHA256 string
}
func encodePublication(v publicationRecord)([]byte,error){
 raw,err:=json.Marshal(v);if err!=nil{return nil,err}
 raw=append(raw,'\n');if len(raw)>maxPublicationRecordBytes{return nil,errors.New("publication record too large")}
 return raw,nil
}
func publicationLock(dir string,bootstrap bool,fn func(string)error)error{
 if strings.TrimSpace(dir)==""{return errors.New("explicit publication ledger directory required")}
 abs,err:=filepath.Abs(dir);if err!=nil{return err}
 if bootstrap{
  // Only a genuinely new directory may initialize a stream. A failed first
  // attempt may leave it empty; never silently reset or reuse it.
  if err:=os.Mkdir(abs,0700);err!=nil{return err}
 }
 if err:=regularDir(abs);err!=nil{return err}
 lock:=filepath.Join(abs,".lock")
 if err:=os.Mkdir(lock,0700);err!=nil{return fmt.Errorf("publication ledger locked: %w",err)}
 defer os.Remove(lock)
 return fn(abs)
}
type ledgerHead struct{
 record *publicationRecord
 hash string
 count int
 total int64
}
// Validate every bounded record in order, including historical TUF signatures
// at its asserted build time and exact snapshot transitions. The hash chain
// is local integrity, not a cryptographically authenticated approval ledger.
func scanPublication(dir,rootPin,authorityPin,expected string)(ledgerHead,error){
 if !hashPattern.MatchString(rootPin)||!hashPattern.MatchString(authorityPin)||expected!=""&&!hashPattern.MatchString(expected){return ledgerHead{},errors.New("explicit independent root and authority pins required")}
 f,err:=os.Open(dir);if err!=nil{return ledgerHead{},err};defer f.Close()
 entries,err:=f.ReadDir(MaxPublicationRecords+2);if err!=nil&&err!=io.EOF{return ledgerHead{},err}
 if len(entries)>MaxPublicationRecords+1{return ledgerHead{},errors.New("publication ledger entry limit")}
 names:=[]string{}
 for _,v:=range entries{
  if v.Name()==".lock"&&v.IsDir(){continue}
  if !v.Type().IsRegular()||!versionName.MatchString(v.Name()){return ledgerHead{},errors.New("unexpected ledger entry; inspect interrupted operation")}
  names=append(names,v.Name())
 }
 sort.Strings(names)
 head:=ledgerHead{}
 for i,name:=range names{
  if name!=evidenceName(uint64(i+1)){return ledgerHead{},errors.New("publication history gap or invalid filename")}
  path:=filepath.Join(dir,name)
  st,err:=os.Lstat(path);if err!=nil{return ledgerHead{},err}
  if !st.Mode().IsRegular()||st.Size()>int64(MaxPublicationLedgerBytes)-head.total{return ledgerHead{},errors.New("publication ledger byte budget exceeded")}
  raw,err:=readRegular(path,maxPublicationRecordBytes);if err!=nil{return ledgerHead{},err}
  if int64(len(raw))>int64(MaxPublicationLedgerBytes)-head.total{return ledgerHead{},errors.New("publication ledger byte budget exceeded")}
  var v publicationRecord
  if err:=json.Unmarshal(raw,&v);err!=nil{return ledgerHead{},err}
  canonical,err:=encodePublication(v)
  if err!=nil||!bytes.Equal(canonical,raw)||v.SchemaVersion!="1"||v.PreviousRecordSHA256!=head.hash||v.AuthoritySHA256!=authorityPin||!hashPattern.MatchString(v.ApprovalSHA256)||!hashPattern.MatchString(v.DossierSHA256)||v.Evidence.Sequence!=uint64(i+1){return ledgerHead{},errors.New("invalid publication record or history link")}
  if _,err:=verifyEvidence(v.Evidence,rootPin,v.Evidence.AcceptedAt);err!=nil{return ledgerHead{},err}
  var prior []byte;var priorPin string
  if head.record!=nil{
   if !rootPrefix(evidenceChain(head.record.Evidence),evidenceChain(v.Evidence)){return ledgerHead{},errors.New("ledger root history rollback or replacement")}
   if v.Evidence.AcceptedAt.Before(head.record.Evidence.AcceptedAt){return ledgerHead{},errors.New("publication build time rollback")}
   prior=head.record.Evidence.Snapshot;priorPin=head.record.Evidence.SnapshotSHA256
  }
  if _,err:=snapshot.CheckPublicationTransition(prior,v.Evidence.Snapshot,priorPin,i==0);err!=nil{return ledgerHead{},err}
  head=ledgerHead{record:&v,hash:digest(raw),count:i+1,total:head.total+int64(len(raw))}
 }
 if expected!=""&&head.hash!=expected{return ledgerHead{},errors.New("independent ledger head pin mismatch")}
 return head,nil
}
func receipt(head ledgerHead,status string)LedgerReceipt{
 v:=head.record
 return LedgerReceipt{Sequence:v.Evidence.Sequence,RecordSHA256:head.hash,PreviousRecordSHA256:v.PreviousRecordSHA256,SnapshotSHA256:v.Evidence.SnapshotSHA256,RootSHA256:digest(v.Evidence.Root),InitialRootSHA256:digest(evidenceChain(v.Evidence)[0]),RootVersion:len(evidenceChain(v.Evidence)),AuthoritySHA256:v.AuthoritySHA256,ApprovalSHA256:v.ApprovalSHA256,DossierSHA256:v.DossierSHA256,BuiltAt:v.Evidence.AcceptedAt,Records:head.count,Status:status,TrustStatus:"NOT_ESTABLISHED"}
}
func repositoryFromRecord(v publicationRecord)Repository{
 e:=v.Evidence
 repo:=Repository{RootSHA256:digest(e.Root),TargetSHA256:e.SnapshotSHA256,Version:int64(e.Sequence),Files:map[string][]byte{
  fmt.Sprintf("metadata/%d.targets.json",e.Sequence):bytes.Clone(e.Targets),
  fmt.Sprintf("metadata/%d.snapshot.json",e.Sequence):bytes.Clone(e.SnapshotMetadata),
  "metadata/timestamp.json":bytes.Clone(e.Timestamp),
  "targets/"+e.SnapshotSHA256+"."+TargetName:bytes.Clone(e.Snapshot),
 }}
 for i,raw:=range evidenceChain(e){repo.Files[fmt.Sprintf("metadata/%d.root.json",i+1)]=bytes.Clone(raw)}
 return repo
}
// BuildInLedger commits exact signed staging bytes before any external
// export. No previous snapshot is accepted from callers in ledger mode.
// A committed record is never overwritten or reused for another snapshot.
func BuildInLedger(rootBytes,raw []byte,o LedgerOptions)(LedgerReceipt,error){
 v:=o.Reviewed
 if len(v.PreviousSnapshot)!=0||v.PreviousSHA256!=""||!hashPattern.MatchString(o.AuthoritySHA256)||v.Approval.AuthoritySHA256!=o.AuthoritySHA256||v.Bootstrap&&o.ExpectedHeadSHA256!=""{return LedgerReceipt{},errors.New("ledger mode requires authority pin and no caller baseline")}
 if !validTime(v.Publish.Now)||v.Publish.Version<1||!hashPattern.MatchString(v.Publish.RootSHA256){return LedgerReceipt{},errors.New("invalid publication time, sequence or root pin")}
 chain:=o.RootChain
 initialPin:=o.InitialRootSHA256
 if len(chain)==0{
  if initialPin!=""{return LedgerReceipt{},errors.New("initial root pin requires explicit chain")}
  chain=[][]byte{rootBytes};initialPin=v.Publish.RootSHA256
 }
 if !bytes.Equal(chain[len(chain)-1],rootBytes){return LedgerReceipt{},errors.New("root differs from chain head")}
 rr,err:=VerifyRootChain(chain,initialPin,v.Publish.Now);if err!=nil{return LedgerReceipt{},err}
 if rr.CurrentRootSHA256!=v.Publish.RootSHA256{return LedgerReceipt{},errors.New("current root pin mismatch")}
 if v.Bootstrap&&(v.Publish.Version!=1||len(chain)!=1){return LedgerReceipt{},errors.New("bootstrap requires root and sequence one")}
 var result LedgerReceipt
 err=publicationLock(o.Directory,v.Bootstrap,func(dir string)error{
  head,err:=scanPublication(dir,initialPin,o.AuthoritySHA256,o.ExpectedHeadSHA256);if err!=nil{return err}
  if head.count>=MaxPublicationRecords{return errors.New("publication ledger full")}
  if v.Bootstrap!=(head.record==nil){return errors.New("explicit new ledger bootstrap or existing nonempty ledger required")}
  if uint64(v.Publish.Version)!=uint64(head.count)+1{return errors.New("publication sequence must advance ledger head exactly once")}
  if head.record!=nil{
   if !rootPrefix(evidenceChain(head.record.Evidence),chain){return errors.New("new root chain must extend exact ledger history")}
   if len(chain)>len(evidenceChain(head.record.Evidence))&&o.ExpectedHeadSHA256==""{return errors.New("independent ledger head pin required for rotation")}
   if v.Publish.Now.Before(head.record.Evidence.AcceptedAt){return errors.New("publication clock rollback")}
   v.PreviousSnapshot=head.record.Evidence.Snapshot;v.PreviousSHA256=head.record.Evidence.SnapshotSHA256
  }
  repo,report,err:=buildReviewedChain(chain,initialPin,raw,v);if err!=nil{return err}
  if report.Authorization.AuthoritySHA256!=o.AuthoritySHA256{return errors.New("verified authority differs from ledger pin")}
  ev:=evidence{SchemaVersion:"1",AcceptedAt:v.Publish.Now,Sequence:uint64(repo.Version),SnapshotSHA256:repo.TargetSHA256,Root:repo.Files[fmt.Sprintf("metadata/%d.root.json",len(chain))],RootHistory:append([][]byte(nil),chain[:len(chain)-1]...),Timestamp:repo.Files["metadata/timestamp.json"],SnapshotMetadata:repo.Files[fmt.Sprintf("metadata/%d.snapshot.json",repo.Version)],Targets:repo.Files[fmt.Sprintf("metadata/%d.targets.json",repo.Version)],Snapshot:repo.Files["targets/"+repo.TargetSHA256+"."+TargetName]}
  if _,err:=verifyEvidence(ev,initialPin,v.Publish.Now);err!=nil{return err}
  record:=publicationRecord{SchemaVersion:"1",PreviousRecordSHA256:head.hash,AuthoritySHA256:o.AuthoritySHA256,ApprovalSHA256:report.Authorization.ApprovalSHA256,DossierSHA256:report.Authorization.Review.DossierSHA256,Evidence:ev}
  data,err:=encodePublication(record);if err!=nil{return err}
  if int64(len(data))>int64(MaxPublicationLedgerBytes)-head.total{return errors.New("publication ledger byte budget exceeded")}
  f,err:=os.CreateTemp(dir,".pending-");if err!=nil{return err}
  defer os.Remove(f.Name())
  if _,err=f.Write(data);err==nil{err=f.Sync()}
  closeErr:=f.Close();if err==nil{err=closeErr};if err!=nil{return err}
  if err:=os.Link(f.Name(),filepath.Join(dir,evidenceName(ev.Sequence)));err!=nil{return err}
  head=ledgerHead{record:&record,hash:digest(data),count:head.count+1,total:head.total+int64(len(data))}
  result=receipt(head,"LOCAL_REVIEWED_BUILD_COMMITTED")
  return nil
 })
 if err!=nil{return LedgerReceipt{},err}
 return result,nil
}
// ExportLedgerHead returns only the latest exact signed staging bytes;
// never regenerate signatures or silently fall back to an older record.
// at must be current for export. No network or actual publication.
func ExportLedgerHead(dir,rootPin,authorityPin,expectedHead string,at time.Time)(Repository,LedgerReceipt,error){
 if !validTime(at){return Repository{},LedgerReceipt{},errors.New("explicit UTC export time required")}
 var repo Repository;var result LedgerReceipt
 err:=publicationLock(dir,false,func(abs string)error{
  head,err:=scanPublication(abs,rootPin,authorityPin,expectedHead);if err!=nil{return err}
  if head.record==nil{return errors.New("publication ledger empty")}
  if _,err:=verifyEvidence(head.record.Evidence,rootPin,at);err!=nil{return err}
  repo=repositoryFromRecord(*head.record);result=receipt(head,"LOCAL_REVIEWED_BUILD_EXPORTED")
  return nil
 })
 if err!=nil{return Repository{},LedgerReceipt{},err}
 return repo,result,nil
}
