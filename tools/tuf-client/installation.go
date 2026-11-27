package tufclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/M78U/trust-registry/pkg/snapshot"
	"github.com/M78U/trust-registry/pkg/review"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const maxInstalled=128
const maxEvidenceBytes=(76<<20)+(MaxRootChain-1)*((maxRoot+2)/3*4+4)
var versionName=regexp.MustCompile(`^[0-9]{20}\.json$`)

type evidence struct {
	SchemaVersion string `json:"schemaVersion"`
	AcceptedAt time.Time `json:"acceptedAt"`
	Sequence uint64 `json:"sequence"`
	SnapshotSHA256 string `json:"snapshotSHA256"`
	Root []byte `json:"root"`
	RootHistory [][]byte `json:"rootHistory,omitempty"`
	Timestamp []byte `json:"timestamp"`
	SnapshotMetadata []byte `json:"snapshotMetadata"`
	Targets []byte `json:"targets"`
	Snapshot []byte `json:"snapshot"`
}

func evidenceName(n uint64)string{return fmt.Sprintf("%020d.json",n)}
func encodeEvidence(v evidence)([]byte,error){b,err:=json.Marshal(v);if err!=nil{return nil,err};return append(b,'\n'),nil}

// Historical roots are verified from the independent v1 pin. V1 records
// omit RootHistory, preserving their original canonical representation.
func verifyEvidence(v evidence,pin string,at time.Time)(Report,error){
	return verifyEvidenceWithChain(v,pin,at,evidenceChain(v))
}

func verifyEvidenceWithChain(v evidence,pin string,at time.Time,chain [][]byte)(Report,error){
	if v.SchemaVersion!="1"||v.Sequence==0||!validTime(v.AcceptedAt)||!validTime(at)||at.Before(v.AcceptedAt)||!hashPattern.MatchString(pin)||len(v.Root)==0||len(v.Root)>maxRoot||len(chain)==0||!bytes.Equal(v.Root,chain[len(chain)-1])||len(v.Timestamp)==0||len(v.Timestamp)>16384||len(v.SnapshotMetadata)==0||len(v.SnapshotMetadata)>2_000_000||len(v.Targets)==0||len(v.Targets)>5_000_000||len(v.Snapshot)==0||len(v.Snapshot)>snapshot.MaxEnvelopeBytes||digest(v.Snapshot)!=v.SnapshotSHA256{return Report{},errors.New("invalid installation evidence or root pin")}
	tr,rr,err:=rootChain(chain,pin,at);if err!=nil{return Report{},err}
	ts,err:=metadata.Timestamp().FromBytes(v.Timestamp);if err!=nil{return Report{},err}
	link:=ts.Signed.Meta["snapshot.json"]
	if link==nil||link.Length<=0||len(link.Hashes["sha256"])!=32{return Report{},errors.New("missing timestamp snapshot hash link")}
	if _,err:=tr.UpdateTimestamp(v.Timestamp);err!=nil{return Report{},err}
	sm,err:=metadata.Snapshot().FromBytes(v.SnapshotMetadata);if err!=nil{return Report{},err}
	link=sm.Signed.Meta["targets.json"]
	if link==nil||link.Length<=0||len(link.Hashes["sha256"])!=32{return Report{},errors.New("missing snapshot targets hash link")}
	if _,err:=tr.UpdateSnapshot(v.SnapshotMetadata,false);err!=nil{return Report{},err}
	tg,err:=tr.UpdateTargets(v.Targets);if err!=nil{return Report{},err}
	info:=tg.Signed.Targets[TargetName]
	if info==nil||info.Path!=TargetName||info.Length<=0||len(info.Hashes)!=1||len(info.Hashes["sha256"])!=32{return Report{},errors.New("missing fixed SHA-256 target")}
	if err:=info.VerifyLengthHashes(v.Snapshot);err!=nil{return Report{},err}
	r,err:=snapshot.Verify(v.Snapshot,"");if err!=nil{return Report{},err}
	if r.Manifest.Sequence!=v.Sequence||r.SnapshotSHA256!=v.SnapshotSHA256||at.Before(r.Manifest.CreatedAt)||!at.Before(r.Manifest.ExpiresAt){return Report{},errors.New("registry identity or expiry mismatch")}
	// The current publisher profile ties application sequence to all three
	// online metadata versions. Fail closed on any other profile.
	if tg.Signed.Version<=0||uint64(tg.Signed.Version)!=v.Sequence||sm.Signed.Version!=tg.Signed.Version||ts.Signed.Version!=tg.Signed.Version{return Report{},errors.New("metadata/application version mismatch")}
	return Report{Target:TargetName,TUFTargetAuthenticated:true,RootVersion:rr.RootVersion,TimestampVersion:ts.Signed.Version,SnapshotMetadataVersion:sm.Signed.Version,TargetsVersion:tg.Signed.Version,Registry:r,ApplicationRollbackStatus:"LOCAL_INSTALLED_RECORD",TrustStatus:"NOT_ESTABLISHED"},nil
}

func latestEvidence(dir string)(*evidence,int,error){
	if err:=regularDir(dir);err!=nil{return nil,0,err}
	f,err:=os.Open(dir);if err!=nil{return nil,0,err};defer f.Close()
	entries,err:=f.ReadDir(maxInstalled+1);if err!=nil&&err!=io.EOF{return nil,0,err}
	if len(entries)>maxInstalled{return nil,0,errors.New("installation history limit")}
	names:=[]string{}
	for _,e:=range entries{
		if !e.Type().IsRegular()||!versionName.MatchString(e.Name()){return nil,0,errors.New("unexpected installation file")}
		names=append(names,e.Name())
	}
	if len(names)==0{return nil,0,nil}
	sort.Strings(names)
	name:=names[len(names)-1]
	raw,err:=readRegular(filepath.Join(dir,name),maxEvidenceBytes);if err!=nil{return nil,0,err}
	var v evidence
	if err:=json.Unmarshal(raw,&v);err!=nil{return nil,0,err}
	canonical,err:=encodeEvidence(v)
	if err!=nil||!bytes.Equal(canonical,raw)||v.Sequence==0||evidenceName(v.Sequence)!=name{return nil,0,errors.New("corrupt installed evidence")}
	return &v,len(names),nil
}

func installEvidence(root,pin string,raw []byte,report Report,at time.Time)error{
	v:=evidence{SchemaVersion:"1",AcceptedAt:at,Sequence:report.Registry.Manifest.Sequence,SnapshotSHA256:digest(raw),Snapshot:raw}
	for _,f:=range []struct{name string;limit int64;dst *[]byte}{{"root.json",maxRoot,&v.Root},{"timestamp.json",16384,&v.Timestamp},{"snapshot.json",2_000_000,&v.SnapshotMetadata},{"targets.json",5_000_000,&v.Targets}}{
		b,err:=readRegular(filepath.Join(root,"metadata",f.name),f.limit);if err!=nil{return err};*f.dst=b
	}
	chain,err:=readRootArchive(root,pin,v.Root,at,false);if err!=nil{return err}
	if report.RootVersion!=int64(len(chain)){return errors.New("root version differs from verified archive")}
	v.RootHistory=append([][]byte(nil),chain[:len(chain)-1]...)
	if _,err:=verifyEvidence(v,pin,at);err!=nil{return err}
	dir,already,err:=checkInstallBaseline(root,pin,v,at);if err!=nil{return err}
	// Idempotent refresh with no interrupted journal needs no disk write.
	if already{if _,err:=os.Lstat(filepath.Join(root,pendingInstallName));os.IsNotExist(err){return nil}else if err!=nil{return err}}
	if err:=stagePendingEvidence(root,v);err!=nil{return err}
	return commitPendingEvidence(root,dir,v,already)
}

// checkInstallBaseline is shared by online install and explicit recovery.
// Caller holds the state lock; no history is removed or rewritten.
func checkInstallBaseline(root,pin string,v evidence,at time.Time)(string,bool,error){
	dir:=filepath.Join(root,"installed")
	if err:=os.Mkdir(dir,0700);err!=nil&&!os.IsExist(err){return "",false,err}
	old,count,err:=latestEvidence(dir);if err!=nil{return "",false,err}
	if old!=nil{
		if v.AcceptedAt.Before(old.AcceptedAt)||at.Before(old.AcceptedAt){return "",false,errors.New("clock earlier than previous acceptance")}
		if _,err:=verifyEvidence(*old,pin,old.AcceptedAt);err!=nil{return "",false,err}
		if !rootPrefix(evidenceChain(*old),evidenceChain(v)){return "",false,errors.New("installed root history rollback or replacement")}
		if v.Sequence<old.Sequence{return "",false,errors.New("registry sequence rollback")}
		if v.Sequence==old.Sequence{
			if len(evidenceChain(*old))!=len(evidenceChain(v))||!bytes.Equal(v.Root,old.Root)||v.SnapshotSHA256!=old.SnapshotSHA256||!bytes.Equal(v.Timestamp,old.Timestamp)||!bytes.Equal(v.SnapshotMetadata,old.SnapshotMetadata)||!bytes.Equal(v.Targets,old.Targets){return "",false,errors.New("same sequence publication conflict")}
			if _,err:=verifyEvidence(*old,pin,at);err!=nil{return "",false,err}
			return dir,true,nil
		}
	}
	if count>=maxInstalled{return "",false,errors.New("installation history full")}
	return dir,false,nil
}

// LoadInstalled opens the latest accepted TUF evidence without networking,
// independently rechecks all signatures/links/expiry, then builds a detached
// read-only Registry view. Caller must protect directory and pinned root hash.
func LoadInstalled(stateDir,initialRootSHA256 string)(*snapshot.Loaded,Report,error){
	return loadInstalled(stateDir,initialRootSHA256,nil)
}

// LoadAuthorizedInstalled requires the same independent authority as strict bootstrap.
func LoadAuthorizedInstalled(stateDir,initialRootSHA256 string,a *review.Authority)(*snapshot.Loaded,Report,error){
	if a==nil{return nil,Report{},errors.New("independent review authority required")}
	return loadInstalled(stateDir,initialRootSHA256,a)
}
func loadInstalled(stateDir,initialRootSHA256 string,a *review.Authority)(*snapshot.Loaded,Report,error){
 return loadInstalledCapture(stateDir,initialRootSHA256,a,nil)
}
func loadInstalledCapture(stateDir,initialRootSHA256 string,a *review.Authority,capture *[]byte)(*snapshot.Loaded,Report,error){
	if stateDir==""||!hashPattern.MatchString(initialRootSHA256){return nil,Report{},errors.New("state and independent initial root pin required")}
	root,err:=filepath.Abs(stateDir);if err!=nil{return nil,Report{},err}
	if err:=regularDir(root);err!=nil{return nil,Report{},err}
	lock:=filepath.Join(root,".lock")
	if err:=os.Mkdir(lock,0700);err!=nil{return nil,Report{},err};defer os.Remove(lock)
	configBytes,err:=readRegular(filepath.Join(root,"configuration.json"),16384);if err!=nil{return nil,Report{},err}
	var cfg stateConfig
	if err:=json.Unmarshal(configBytes,&cfg);err!=nil{return nil,Report{},err}
	canonical,err:=json.Marshal(cfg);if err!=nil||!bytes.Equal(canonical,configBytes)||cfg.SchemaVersion!="1"||cfg.InitialRootSHA256!=initialRootSHA256||cfg.ReviewAuthoritySHA256!=a.SHA256(){return nil,Report{},errors.New("installed state identity or review authority mismatch")}
	v,_,err:=latestEvidence(filepath.Join(root,"installed"));if err!=nil{return nil,Report{},err}
	if v==nil{return nil,Report{},errors.New("no installed evidence")}
	// A refresh can advance cache metadata before installation commits. Do
	// not silently use an older installed record when that has happened.
	if err:=regularDir(filepath.Join(root,"metadata"));err!=nil{return nil,Report{},err}
	for _,f:=range []struct{name string;limit int64;expected []byte}{
		{"root.json",maxRoot,v.Root},{"timestamp.json",16384,v.Timestamp},
		{"snapshot.json",2_000_000,v.SnapshotMetadata},{"targets.json",5_000_000,v.Targets},
	}{
		cached,err:=readRegular(filepath.Join(root,"metadata",f.name),f.limit);if err!=nil{return nil,Report{},err}
		if !bytes.Equal(cached,f.expected){return nil,Report{},errors.New("cached metadata differs from installed evidence; successful refresh/install required")}
	}
	at:=time.Now().UTC()
	chain,err:=readRootArchive(root,initialRootSHA256,v.Root,at,false);if err!=nil{return nil,Report{},err}
	if len(chain)!=len(evidenceChain(*v))||!rootPrefix(evidenceChain(*v),chain){return nil,Report{},errors.New("installed root chain differs from archive")}
	report,err:=verifyEvidence(*v,initialRootSHA256,at);if err!=nil{return nil,Report{},err}
	if a!=nil{
		tg,err:=metadata.Targets().FromBytes(v.Targets);if err!=nil{return nil,Report{},err}
		sm,err:=metadata.Snapshot().FromBytes(v.SnapshotMetadata);if err!=nil{return nil,Report{},err}
		ts,err:=metadata.Timestamp().FromBytes(v.Timestamp);if err!=nil{return nil,Report{},err}
		approval,err:=checkPublicCredential(a,chain,initialRootSHA256,tg.Signed.Targets[TargetName],tg.Signed.Version,tg.Signed.Expires,sm.Signed.Expires,ts.Signed.Expires,at);if err!=nil{return nil,Report{},err}
		report.ReleaseApproval=&approval
	}
	view,_,err:=snapshot.LoadPinnedResearch(v.Snapshot,v.SnapshotSHA256,at);if err!=nil{return nil,Report{},err}
 // Derive the offline validity bound from the exact authenticated metadata.
 rootMeta,err:=metadata.Root().FromBytes(v.Root);if err!=nil{return nil,Report{},err}
 tsMeta,err:=metadata.Timestamp().FromBytes(v.Timestamp);if err!=nil{return nil,Report{},err}
 smMeta,err:=metadata.Snapshot().FromBytes(v.SnapshotMetadata);if err!=nil{return nil,Report{},err}
 tgMeta,err:=metadata.Targets().FromBytes(v.Targets);if err!=nil{return nil,Report{},err}
 until:=report.Registry.Manifest.ExpiresAt
 for _,expires:=range []time.Time{rootMeta.Signed.Expires,tsMeta.Signed.Expires,smMeta.Signed.Expires,tgMeta.Signed.Expires}{if expires.Before(until){until=expires}}
 finished:=time.Now().UTC()
 if finished.Before(at)||!finished.Before(until){return nil,Report{},errors.New("offline verification expired or clock moved backward during load")}
 report.OfflineVerification=&OfflineVerification{VerifiedAt:at,ValidUntil:until}
 if capture!=nil{*capture=v.Snapshot}
 return view,report,nil
}
