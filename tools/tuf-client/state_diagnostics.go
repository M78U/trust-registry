package tufclient

import (
 "bytes"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
 "github.com/theupdateframework/go-tuf/v2/metadata"
)

type DiagnosticOptions struct {
 StateDir string
 InitialRootSHA256 string
 Authority *review.Authority
 Checkpoint *ReleaseCheckpoint
}

// StateDiagnostic contains no paths, certificate bytes, source URLs or raw
// errors. Status and recommendation are fixed local diagnostic codes.
type StateDiagnostic struct {
 Status string `json:"status"`
 Recommendation string `json:"recommendation"`
 CheckedAt time.Time `json:"checkedAt"`
 CachedRootVersion int64 `json:"cachedRootVersion,omitempty"`
 ArchivedRootVersion int64 `json:"archivedRootVersion,omitempty"`
 ArchivedHeadSHA256 string `json:"archivedHeadSHA256,omitempty"`
 Installed *DiagnosticEvidence `json:"installed,omitempty"`
 Pending *DiagnosticEvidence `json:"pending,omitempty"`
 PendingPresent bool `json:"pendingPresent"`
 CheckpointProvided bool `json:"checkpointProvided"`
 TrustStatus string `json:"trustStatus"`
}

type DiagnosticEvidence struct {
 Sequence uint64 `json:"sequence"`
 SnapshotSHA256 string `json:"snapshotSHA256"`
 RootVersion int64 `json:"rootVersion"`
 ValidUntil time.Time `json:"validUntil"`
 CacheMatches bool `json:"cacheMatches"`
 Expired bool `json:"expired"`
 CheckpointMatches bool `json:"checkpointMatches"`
}

// DiagnoseState obtains only the cooperative lock, reads bounded local files,
// and emits advisory findings. It never commits, repairs or loads a consumer.
func DiagnoseState(o DiagnosticOptions) (StateDiagnostic,error) {
 return diagnoseStateAt(o,time.Now().UTC())
}

func diagnoseStateAt(o DiagnosticOptions,at time.Time)(StateDiagnostic,error){
 if o.StateDir==""||!hashPattern.MatchString(o.InitialRootSHA256)||o.Authority==nil||!hashPattern.MatchString(o.Authority.SHA256())||!validTime(at){
  return StateDiagnostic{},errors.New("strict state, independent root/authority and UTC clock required")
 }
 var checkpoint *ReleaseCheckpoint
 if o.Checkpoint!=nil{c:=*o.Checkpoint;if err:=c.validate();err!=nil{return StateDiagnostic{},err};checkpoint=&c}
 d:=StateDiagnostic{CheckedAt:at,CheckpointProvided:checkpoint!=nil,TrustStatus:"NOT_ESTABLISHED"}
 finish:=func(status,action string)(StateDiagnostic,error){d.Status=status;d.Recommendation=action;return d,nil}
 root,err:=filepath.Abs(o.StateDir);if err!=nil{return StateDiagnostic{},err}
 if err:=regularDir(root);err!=nil{
  if os.IsNotExist(err){return finish("STATE_MISSING","INSPECT_BEFORE_EXPLICIT_BOOTSTRAP_WITH_PINS_AND_CHECKPOINT")}
  return finish("STATE_INVALID","INSPECT_PRIVATE_STATE")
 }
 lock:=filepath.Join(root,".lock")
 if err:=os.Mkdir(lock,0700);err!=nil{
  if os.IsExist(err){return finish("STATE_LOCKED","CHECK_ACTIVE_WRITER_DO_NOT_BREAK_LOCK")}
  return finish("LOCK_UNAVAILABLE","INSPECT_PRIVATE_STATE")
 }
 defer os.Remove(lock)
 raw,err:=readRegular(filepath.Join(root,"configuration.json"),16384)
 if err!=nil{return finish("CONFIGURATION_INVALID","INSPECT_PRIVATE_STATE")}
 var cfg stateConfig
 if err:=json.Unmarshal(raw,&cfg);err!=nil{return finish("CONFIGURATION_INVALID","INSPECT_PRIVATE_STATE")}
 canonical,err:=json.Marshal(cfg)
 if err!=nil||!bytes.Equal(raw,canonical)||cfg.SchemaVersion!="1"||cfg.InitialRootSHA256!=o.InitialRootSHA256||cfg.ReviewAuthoritySHA256!=o.Authority.SHA256(){return finish("CONFIGURATION_MISMATCH","VERIFY_INDEPENDENT_PINS_AND_STATE")}
 pendingPath:=filepath.Join(root,pendingInstallName)
 if _,err:=os.Lstat(pendingPath);err==nil{d.PendingPresent=true}else if !os.IsNotExist(err){return finish("PENDING_UNREADABLE","INSPECT_PRIVATE_STATE")}
 metaDir:=filepath.Join(root,"metadata")
 if err:=regularDir(metaDir);err!=nil{return finish("METADATA_INVALID","INSPECT_PRIVATE_STATE")}
 cached,err:=readRegular(filepath.Join(metaDir,"root.json"),maxRoot)
 if err!=nil{return finish("ROOT_CACHE_INVALID","INSPECT_PRIVATE_STATE")}
 var chain [][]byte
 if _,err:=os.Lstat(filepath.Join(root,"roots"));os.IsNotExist(err){
  chain,err=readRootArchive(root,o.InitialRootSHA256,cached,at,false)
  if err!=nil{return finish("ROOT_ARCHIVE_INVALID","INSPECT_PRIVATE_STATE")}
 }else{
  if err!=nil{return finish("ROOT_ARCHIVE_INVALID","INSPECT_PRIVATE_STATE")}
  chain,err=readNumberedRootArchive(filepath.Join(root,"roots"),o.InitialRootSHA256,at)
  if err!=nil{return finish("ROOT_ARCHIVE_INVALID","INSPECT_PRIVATE_STATE")}
 }
 for i,b:=range chain{
  m,err:=metadata.Root().FromBytes(b);if err!=nil||strictRootProfile(m,o.Authority)!=nil{return finish("ROOT_ARCHIVE_INVALID","INSPECT_PRIVATE_STATE")}
  if bytes.Equal(b,cached){d.CachedRootVersion=int64(i+1)}
 }
 d.ArchivedRootVersion=int64(len(chain));d.ArchivedHeadSHA256=digest(chain[len(chain)-1])
 if d.CachedRootVersion==0{return finish("ROOT_CACHE_NOT_ARCHIVED","INSPECT_PRIVATE_STATE")}
 var old *evidence
 var count int
 installedDir:=filepath.Join(root,"installed")
 if _,err:=os.Lstat(installedDir);err==nil{
  old,count,err=latestEvidence(installedDir)
  if err!=nil{return finish("INSTALLED_HISTORY_INVALID","INSPECT_PRIVATE_STATE")}
 }else if !os.IsNotExist(err){return finish("INSTALLED_HISTORY_INVALID","INSPECT_PRIVATE_STATE")}
 if old!=nil{
  if !rootPrefix(evidenceChain(*old),chain){return finish("INSTALLED_ROOT_CONFLICT","INSPECT_PRIVATE_STATE")}
  info,err:=diagnosticEvidence(*old,o.InitialRootSHA256,o.Authority,at,checkpoint)
  if err!=nil{return finish("INSTALLED_EVIDENCE_INVALID","INSPECT_PRIVATE_STATE")}
  d.Installed=&info
 }
 if d.CachedRootVersion<d.ArchivedRootVersion{
  if checkpoint!=nil&&d.ArchivedRootVersion<checkpoint.RootVersion{return finish("ROOT_BELOW_CHECKPOINT","INSPECT_PRIVATE_STATE")}
  return finish("ROOT_CACHE_BEHIND_ARCHIVE","REVIEW_HEAD_THEN_RECOVER_ROOT_CACHE")
 }
 // Read each online metadata file once. Missing files are a distinct
 // incomplete-cache case, not evidence of a verified newer release.
 cache:=[][]byte{cached}
 complete:=true
 for _,f:=range []struct{name string;limit int64}{{"timestamp.json",16384},{"snapshot.json",2_000_000},{"targets.json",5_000_000}}{
  b,err:=readRegular(filepath.Join(metaDir,f.name),f.limit)
  if err!=nil{
   if !os.IsNotExist(err){return finish("METADATA_INVALID","INSPECT_PRIVATE_STATE")}
   complete=false
  }
  cache=append(cache,b)
 }
 matches:=func(v evidence)bool{
  return complete&&len(evidenceChain(v))==len(chain)&&rootPrefix(evidenceChain(v),chain)&&bytes.Equal(cache[0],v.Root)&&bytes.Equal(cache[1],v.Timestamp)&&bytes.Equal(cache[2],v.SnapshotMetadata)&&bytes.Equal(cache[3],v.Targets)
 }
 if old!=nil{d.Installed.CacheMatches=matches(*old)}
 if d.PendingPresent{
  raw,err:=readRegular(pendingPath,maxEvidenceBytes)
  if err!=nil{return finish("PENDING_INVALID","INSPECT_PRIVATE_STATE")}
  var v evidence
  if err:=json.Unmarshal(raw,&v);err!=nil{return finish("PENDING_INVALID","INSPECT_PRIVATE_STATE")}
  canonical,err:=encodeEvidence(v)
  if err!=nil||!bytes.Equal(canonical,raw){return finish("PENDING_INVALID","INSPECT_PRIVATE_STATE")}
  info,err:=diagnosticEvidence(v,o.InitialRootSHA256,o.Authority,at,checkpoint)
  if err!=nil{return finish("PENDING_INVALID","INSPECT_PRIVATE_STATE")}
  info.CacheMatches=matches(v);d.Pending=&info
  if !info.CacheMatches{return finish("PENDING_CACHE_MISMATCH","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
  if info.Expired{return finish("PENDING_EXPIRED","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
  if !info.CheckpointMatches{return finish("PENDING_BELOW_CHECKPOINT","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
  if old!=nil{
   if v.AcceptedAt.Before(old.AcceptedAt)||v.Sequence<old.Sequence||!rootPrefix(evidenceChain(*old),evidenceChain(v)){return finish("PENDING_HISTORY_CONFLICT","INSPECT_PRIVATE_STATE")}
   if v.Sequence==old.Sequence{
    if !d.Installed.CacheMatches||v.SnapshotSHA256!=old.SnapshotSHA256{return finish("PENDING_HISTORY_CONFLICT","INSPECT_PRIVATE_STATE")}
    if d.Installed.Expired{return finish("INSTALLED_EXPIRED","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
    return finish("PENDING_COMMITTED_CLEANUP","RECOVER_PENDING_INSTALL")
   }
  }
  if count>=maxInstalled{return finish("INSTALL_HISTORY_FULL","INSPECT_PRIVATE_STATE")}
  return finish("PENDING_RECOVERY_CANDIDATE","RECOVER_PENDING_INSTALL")
 }
 if !complete{return finish("METADATA_INCOMPLETE","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
 if old==nil{return finish("NO_INSTALLED_EVIDENCE","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
 if !d.Installed.CacheMatches{return finish("INSTALLED_CACHE_MISMATCH","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
 if !d.Installed.CheckpointMatches{return finish("INSTALLED_BELOW_CHECKPOINT","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
 if d.Installed.Expired{return finish("INSTALLED_EXPIRED","VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT")}
 return finish("INSTALLED_EVIDENCE_MATCHES","OPEN_STRICT_CONSUMER")
}

// Verify at recorded acceptance before using signed expiry fields to label
// stale data. A diagnostic never treats historical verification as current.
func diagnosticEvidence(v evidence,pin string,a *review.Authority,at time.Time,c *ReleaseCheckpoint)(DiagnosticEvidence,error){
 if !validTime(v.AcceptedAt)||at.Before(v.AcceptedAt){return DiagnosticEvidence{},errors.New("invalid acceptance time")}
 r,err:=verifyEvidence(v,pin,v.AcceptedAt);if err!=nil{return DiagnosticEvidence{},err}
 tg,err:=metadata.Targets().FromBytes(v.Targets);if err!=nil{return DiagnosticEvidence{},err}
 sm,err:=metadata.Snapshot().FromBytes(v.SnapshotMetadata);if err!=nil{return DiagnosticEvidence{},err}
 ts,err:=metadata.Timestamp().FromBytes(v.Timestamp);if err!=nil{return DiagnosticEvidence{},err}
 rt,err:=metadata.Root().FromBytes(v.Root);if err!=nil{return DiagnosticEvidence{},err}
 if _,err:=checkPublicCredential(a,evidenceChain(v),pin,tg.Signed.Targets[TargetName],tg.Signed.Version,tg.Signed.Expires,sm.Signed.Expires,ts.Signed.Expires,v.AcceptedAt);err!=nil{return DiagnosticEvidence{},err}
 until:=r.Registry.Manifest.ExpiresAt
 for _,e:=range []time.Time{rt.Signed.Expires,tg.Signed.Expires,sm.Signed.Expires,ts.Signed.Expires}{if e.Before(until){until=e}}
 info:=DiagnosticEvidence{Sequence:v.Sequence,SnapshotSHA256:v.SnapshotSHA256,RootVersion:r.RootVersion,ValidUntil:until,Expired:!at.Before(until),CheckpointMatches:c==nil||c.check(v.Sequence,v.SnapshotSHA256,r.RootVersion)==nil}
 if !info.Expired{
  if _,err:=checkPublicCredential(a,evidenceChain(v),pin,tg.Signed.Targets[TargetName],tg.Signed.Version,tg.Signed.Expires,sm.Signed.Expires,ts.Signed.Expires,at);err!=nil{return DiagnosticEvidence{},err}
 }
 return info,nil
}
