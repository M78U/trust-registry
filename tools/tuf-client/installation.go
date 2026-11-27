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
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

const maxInstalled=128
const maxEvidenceBytes=76<<20
var versionName=regexp.MustCompile(`^[0-9]{20}\.json$`)

type evidence struct {
	SchemaVersion string `json:"schemaVersion"`
	AcceptedAt time.Time `json:"acceptedAt"`
	Sequence uint64 `json:"sequence"`
	SnapshotSHA256 string `json:"snapshotSHA256"`
	Root []byte `json:"root"`
	Timestamp []byte `json:"timestamp"`
	SnapshotMetadata []byte `json:"snapshotMetadata"`
	Targets []byte `json:"targets"`
	Snapshot []byte `json:"snapshot"`
}

func evidenceName(n uint64)string{return fmt.Sprintf("%020d.json",n)}
func encodeEvidence(v evidence)([]byte,error){b,err:=json.Marshal(v);if err!=nil{return nil,err};return append(b,'\n'),nil}

// Offline verification intentionally supports only the independently pinned
// version-one root. No trusting a rotated root from the mutable cache.
func verifyEvidence(v evidence,pin string,at time.Time)(Report,error){
	if v.SchemaVersion!="1"||v.Sequence==0||!validTime(v.AcceptedAt)||!validTime(at)||at.Before(v.AcceptedAt)||!hashPattern.MatchString(pin)||len(v.Root)==0||len(v.Root)>maxRoot||digest(v.Root)!=pin||len(v.Timestamp)==0||len(v.Timestamp)>16384||len(v.SnapshotMetadata)==0||len(v.SnapshotMetadata)>2_000_000||len(v.Targets)==0||len(v.Targets)>5_000_000||len(v.Snapshot)==0||len(v.Snapshot)>snapshot.MaxEnvelopeBytes||digest(v.Snapshot)!=v.SnapshotSHA256{return Report{},errors.New("invalid installation evidence or root pin")}
	tr,err:=trustedmetadata.New(v.Root);if err!=nil{return Report{},err}
	if tr.Root.Signed.Version!=1||!tr.Root.Signed.ConsistentSnapshot{return Report{},errors.New("offline installation requires pinned initial consistent root")}
	tr.RefTime=at
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
	return Report{Target:TargetName,TUFTargetAuthenticated:true,RootVersion:1,TimestampVersion:ts.Signed.Version,SnapshotMetadataVersion:sm.Signed.Version,TargetsVersion:tg.Signed.Version,Registry:r,ApplicationRollbackStatus:"LOCAL_INSTALLED_RECORD",TrustStatus:"NOT_ESTABLISHED"},nil
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
	if report.RootVersion!=1{return errors.New("rotated-root offline installation not supported")}
	v:=evidence{SchemaVersion:"1",AcceptedAt:at,Sequence:report.Registry.Manifest.Sequence,SnapshotSHA256:digest(raw),Snapshot:raw}
	for _,f:=range []struct{name string;limit int64;dst *[]byte}{{"root.json",maxRoot,&v.Root},{"timestamp.json",16384,&v.Timestamp},{"snapshot.json",2_000_000,&v.SnapshotMetadata},{"targets.json",5_000_000,&v.Targets}}{
		b,err:=readRegular(filepath.Join(root,"metadata",f.name),f.limit);if err!=nil{return err};*f.dst=b
	}
	if _,err:=verifyEvidence(v,pin,at);err!=nil{return err}
	dir:=filepath.Join(root,"installed")
	if err:=os.Mkdir(dir,0700);err!=nil&&!os.IsExist(err){return err}
	old,count,err:=latestEvidence(dir);if err!=nil{return err}
	if old!=nil{
		if at.Before(old.AcceptedAt){return errors.New("clock earlier than previous acceptance")}
		if _,err:=verifyEvidence(*old,pin,old.AcceptedAt);err!=nil{return err}
		if v.Sequence<old.Sequence{return errors.New("registry sequence rollback")}
		if v.Sequence==old.Sequence{
			if v.SnapshotSHA256!=old.SnapshotSHA256||!bytes.Equal(v.Timestamp,old.Timestamp)||!bytes.Equal(v.SnapshotMetadata,old.SnapshotMetadata)||!bytes.Equal(v.Targets,old.Targets){return errors.New("same sequence publication conflict")}
			_,err:=verifyEvidence(*old,pin,at);return err
		}
	}
	if count>=maxInstalled{return errors.New("installation history full")}
	data,err:=encodeEvidence(v);if err!=nil{return err}
	if len(data)>maxEvidenceBytes{return errors.New("installation evidence too large")}
	f,err:=os.CreateTemp(dir,".pending-");if err!=nil{return err}
	defer os.Remove(f.Name())
	if _,err=f.Write(data);err==nil{err=f.Sync()}
	e:=f.Close();if err==nil{err=e};if err!=nil{return err}
	return os.Link(f.Name(),filepath.Join(dir,evidenceName(v.Sequence)))
}

// LoadInstalled opens the latest accepted TUF evidence without networking,
// independently rechecks all signatures/links/expiry, then builds a detached
// read-only Registry view. Caller must protect directory and pinned root hash.
func LoadInstalled(stateDir,initialRootSHA256 string)(*snapshot.Loaded,Report,error){
	if stateDir==""||!hashPattern.MatchString(initialRootSHA256){return nil,Report{},errors.New("state and independent initial root pin required")}
	root,err:=filepath.Abs(stateDir);if err!=nil{return nil,Report{},err}
	if err:=regularDir(root);err!=nil{return nil,Report{},err}
	lock:=filepath.Join(root,".lock")
	if err:=os.Mkdir(lock,0700);err!=nil{return nil,Report{},err};defer os.Remove(lock)
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
	report,err:=verifyEvidence(*v,initialRootSHA256,at);if err!=nil{return nil,Report{},err}
	view,_,err:=snapshot.LoadPinnedResearch(v.Snapshot,v.SnapshotSHA256,at);if err!=nil{return nil,Report{},err}
	return view,report,nil
}
