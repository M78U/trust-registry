package snapshot

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

const MaxInstalledVersions = 128
const MaxInstalledRecordBytes = (64 << 20) + (128 << 10)
var installedName = regexp.MustCompile(`^([0-9]{20})-([a-f0-9]{64})\.json$`)

type InstallationOptions struct {
	Keys []ed25519.PublicKey
	Threshold int
	At time.Time
	Bootstrap bool
}

type installedRecord struct {
	SchemaVersion string `json:"schemaVersion"`
	KeyConfigurationSHA256 string `json:"keyConfigurationSHA256"`
	AcceptedAt time.Time `json:"acceptedAt"`
	Checkpoint Checkpoint `json:"checkpoint"`
	Snapshot []byte `json:"snapshot"`
	Signatures []Signature `json:"signatures"`
}

type InstallationReport struct {
	Status string `json:"status"`
	Authentication ResearchAuthentication `json:"authentication"`
	Checkpoint Checkpoint `json:"checkpoint"`
	AcceptedAt time.Time `json:"acceptedAt"`
	KeyConfigurationSHA256 string `json:"keyConfigurationSHA256"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
	TrustStatus string `json:"trustStatus"`
}

func configDigest(o InstallationOptions)(string,error){
	if !utc(o.At)||len(o.Keys)==0||len(o.Keys)>MaxResearchKeys||o.Threshold<1||o.Threshold>len(o.Keys){return "",errors.New("invalid installation configuration")}
	ids:=make([]string,0,len(o.Keys))
	seen:=map[string]bool{}
	for _,k:=range o.Keys{
		id,err:=KeyID(k);if err!=nil{return "",err}
		if seen[id]{return "",errors.New("duplicate pinned key")}
		seen[id]=true;ids=append(ids,id)
	}
	sort.Strings(ids)
	raw,err:=canonical(struct{Threshold int `json:"threshold"`;KeyIDs []string `json:"keyIds"`}{o.Threshold,ids})
	if err!=nil{return "",err}
	return digest(raw),nil
}

// withInstallationLock serializes cooperative readers/writers. The state
// directory and its parents must be private, caller-controlled local storage.
// A stale lock after a crash is deliberately not automatically removed.
func withInstallationLock(root string,bootstrap bool,fn func(string)error)error{
	if root==""{return errors.New("installation directory required")}
	abs,err:=filepath.Abs(root);if err!=nil{return err}
	if bootstrap{
		if err:=os.Mkdir(abs,0700);err!=nil{return fmt.Errorf("bootstrap requires a new installation directory: %w",err)}
	}
	info,err:=os.Lstat(abs);if err!=nil{return err}
	if !info.IsDir(){return errors.New("installation must be a regular directory")}
	lock:=filepath.Join(abs,".lock")
	if err:=os.Mkdir(lock,0700);err!=nil{return fmt.Errorf("installation lock unavailable: %w",err)}
	defer os.Remove(lock)
	return fn(abs)
}

func recordName(c Checkpoint)string{return fmt.Sprintf("%020d-%s.json",c.Sequence,c.SnapshotSHA256)}

// latestRecord never falls back to an earlier version. Unrecognized names,
// duplicate sequences or an exceeded history limit fail closed.
func latestRecord(root string)(string,int,error){
	f,err:=os.Open(root);if err!=nil{return "",0,err};defer f.Close()
	entries,err:=f.ReadDir(MaxInstalledVersions+2)
	if err!=nil&&err!=io.EOF{return "",0,err}
	if len(entries)>MaxInstalledVersions+1{return "",0,errors.New("installation history limit exceeded")}
	seen:=map[uint64]bool{}
	var newest uint64
	var latest string
	count:=0
	for _,e:=range entries{
		if e.Name()==".lock"&&e.IsDir(){continue}
		m:=installedName.FindStringSubmatch(e.Name())
		if len(m)!=3||!e.Type().IsRegular(){return "",0,errors.New("unexpected installation entry")}
		seq,err:=strconv.ParseUint(m[1],10,64);if err!=nil||seq==0||seen[seq]{return "",0,errors.New("invalid or duplicate installed sequence")}
		seen[seq]=true;count++
		if seq>newest{newest=seq;latest=e.Name()}
	}
	return latest,count,nil
}

func readInstalled(path string)(installedRecord,error){
	var rec installedRecord
	info,err:=os.Lstat(path);if err!=nil{return rec,err}
	if !info.Mode().IsRegular()||info.Size()>MaxInstalledRecordBytes{return rec,errors.New("invalid installed record type or size")}
	f,err:=os.Open(path);if err!=nil{return rec,err};defer f.Close()
	opened,err:=f.Stat();if err!=nil{return rec,err}
	if !opened.Mode().IsRegular()||!os.SameFile(info,opened){return rec,errors.New("installed record changed while opening")}
	raw,err:=io.ReadAll(io.LimitReader(f,MaxInstalledRecordBytes+1));if err!=nil{return rec,err}
	if len(raw)>MaxInstalledRecordBytes{return rec,errors.New("installed record size limit exceeded")}
	if err:=json.Unmarshal(raw,&rec);err!=nil{return rec,err}
	encoded,err:=canonical(rec)
	if err!=nil||!bytes.Equal(encoded,raw)||rec.SchemaVersion!="1"||!utc(rec.AcceptedAt)||!hashPattern.MatchString(rec.KeyConfigurationSHA256)||rec.Checkpoint.Sequence==0||!hashPattern.MatchString(rec.Checkpoint.SnapshotSHA256)||recordName(rec.Checkpoint)!=filepath.Base(path){return installedRecord{},errors.New("invalid installed record")}
	return rec,nil
}

func authenticateInstalled(rec installedRecord,config string,o InstallationOptions,at time.Time)(ResearchAuthentication,error){
	if rec.KeyConfigurationSHA256!=config{return ResearchAuthentication{},errors.New("pinned key configuration changed; rotation not supported")}
	if at.Before(rec.AcceptedAt){return ResearchAuthentication{},errors.New("clock earlier than installation acceptance")}
	auth,err:=AuthenticateResearch(rec.Snapshot,rec.Signatures,o.Keys,o.Threshold,at,&rec.Checkpoint)
	if err!=nil{return ResearchAuthentication{},err}
	if auth.NextCheckpoint!=rec.Checkpoint{return ResearchAuthentication{},errors.New("installed checkpoint mismatch")}
	return auth,nil
}

func reportInstalled(status string,rec installedRecord,auth ResearchAuthentication)InstallationReport{
	return InstallationReport{Status:status,Authentication:auth,Checkpoint:rec.Checkpoint,AcceptedAt:rec.AcceptedAt,KeyConfigurationSHA256:rec.KeyConfigurationSHA256,TrustStatus:"NOT_ESTABLISHED"}
}

// commitRecord installs one complete append-only record via a same-directory
// hard link, without overwriting. No active-pointer/checkpoint split.
func commitRecord(root string,rec installedRecord)error{
	raw,err:=canonical(rec);if err!=nil{return err}
	if len(raw)>MaxInstalledRecordBytes{return errors.New("installed record too large")}
	f,err:=os.CreateTemp(root,".pending-");if err!=nil{return err}
	defer os.Remove(f.Name())
	if _,err=f.Write(raw);err==nil{err=f.Sync()}
	closeErr:=f.Close();if err==nil{err=closeErr}
	if err!=nil{return err}
	return os.Link(f.Name(),filepath.Join(root,recordName(rec.Checkpoint)))
}

// InstallResearch authenticates before installing and compares against the
// latest accepted record. Bootstrap must be explicit for a new directory
// and is forbidden after acceptance. No network or production release trust.
func InstallResearch(root string,raw []byte,sigs []Signature,o InstallationOptions)(InstallationReport,error){
	config,err:=configDigest(o);if err!=nil{return InstallationReport{},err}
	if o.Bootstrap {
		// Validate before creating state so bad signatures cannot leave empty state.
		if _,err:=AuthenticateResearch(raw,sigs,o.Keys,o.Threshold,o.At,nil);err!=nil{return InstallationReport{},err}
	}
	var result InstallationReport
	err=withInstallationLock(root,o.Bootstrap,func(dir string)error{
		latest,count,err:=latestRecord(dir);if err!=nil{return err}
		var previous *Checkpoint
		var prior installedRecord
		if latest==""{
			if !o.Bootstrap{return errors.New("explicit bootstrap required for empty installation")}
		}else{
			if o.Bootstrap{return errors.New("bootstrap prohibited for existing installation")}
			prior,err=readInstalled(filepath.Join(dir,latest));if err!=nil{return err}
			if o.At.Before(prior.AcceptedAt){return errors.New("clock earlier than previous acceptance")}
			// Verify previous signatures at their recorded acceptance time.
			// Expiration of an older snapshot must not prevent a valid update.
			if _,err:=authenticateInstalled(prior,config,o,prior.AcceptedAt);err!=nil{return err}
			previous=&prior.Checkpoint
		}
		auth,err:=AuthenticateResearch(raw,sigs,o.Keys,o.Threshold,o.At,previous);if err!=nil{return err}
		if previous!=nil&&auth.NextCheckpoint==*previous{
			verified,err:=authenticateInstalled(prior,config,o,o.At);if err!=nil{return err}
			result=reportInstalled("ALREADY_INSTALLED",prior,verified);return nil
		}
		if count>=MaxInstalledVersions{return errors.New("installation history full")}
		ordered:=append([]Signature{},sigs...)
		sort.Slice(ordered,func(i,j int)bool{return ordered[i].KeyID<ordered[j].KeyID})
		rec:=installedRecord{"1",config,o.At,auth.NextCheckpoint,raw,ordered}
		if err:=commitRecord(dir,rec);err!=nil{return err}
		result=reportInstalled("INSTALLED_RESEARCH_SNAPSHOT",rec,auth)
		return nil
	})
	if err!=nil{return InstallationReport{},err}
	return result,nil
}
