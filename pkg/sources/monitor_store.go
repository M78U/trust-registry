package sources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const MaxMonitorHistory = 512
const MaxMonitorIndexBytes = 1 << 20

// MonitorHistory is a bounded local index of asserted receipts. Only the
// latest original is replayed during ordinary reads. This is not a signed
// ledger, and a local filesystem attacker can replace or roll back the index.
type MonitorHistory struct {
	SchemaVersion string `json:"schemaVersion"`
	Source MonitorSource `json:"source"`
	Mode string `json:"mode"`
	Observations []SourceObservationReceipt `json:"observations"`
	TrustStatus string `json:"trustStatus"`
}

type MonitorStoreResult struct {
	Status string `json:"status"`
	Observation SourceObservationReceipt `json:"observation"`
	Count int `json:"count"`
	Diff *SourceObservationDiff `json:"diff,omitempty"`
	TrustStatus string `json:"trustStatus"`
}

func monitorPrivateDir(path string) error {
	if path=="" { return errors.New("existing private monitor directory required") }
	st,err:=os.Lstat(path)
	if err!=nil { return err }
	if !st.IsDir() || st.Mode().Perm()&0077!=0 { return errors.New("monitor directory must be a real private directory (0700)") }
	return nil
}

func monitorStream(root,id,mode string)(string,MonitorSource,error){
	s,err:=monitorSource(id)
	if err!=nil{return "",s,err}
	if mode!="HTTPS_RESPONSE" && mode!="LOCAL_INPUT"{return "",s,errors.New("unknown observation mode")}
	if err:=monitorPrivateDir(root);err!=nil{return "",s,err}
	return filepath.Join(root,id+"-"+mode),s,nil
}
func emptyMonitorHistory(s MonitorSource,mode string)MonitorHistory{
	return MonitorHistory{SchemaVersion:"1",Source:s,Mode:mode,Observations:[]SourceObservationReceipt{},TrustStatus:"NOT_ESTABLISHED"}
}
func monitorIndexBytes(h MonitorHistory)([]byte,error){
	b,err:=json.Marshal(h)
	if err!=nil{return nil,err}
	b=append(b,'\n')
	if len(b)>MaxMonitorIndexBytes{return nil,errors.New("monitor index size limit")}
	return b,nil
}
func validateMonitorHistory(h MonitorHistory,s MonitorSource,mode string)error{
	if h.SchemaVersion!="1"||h.Source!=s||h.Mode!=mode||h.TrustStatus!="NOT_ESTABLISHED"||h.Observations==nil||len(h.Observations)>MaxMonitorHistory{return errors.New("invalid monitor index")}
	var previous time.Time
	seen:=map[string]bool{}
	for _,r:=range h.Observations{
		if r.Source!=s||r.Mode!=mode||!intakeTime(r.RecordedAt)||!r.RecordedAt.After(previous)||!sha256Pattern.MatchString(r.ObservationSHA256)||!sha256Pattern.MatchString(r.BodySHA256)||r.BodyBytes<1||r.BodyBytes>MaxSourceBodyBytes||r.SourceAuthentication!="NOT_ESTABLISHED"||r.TrustStatus!="NOT_ESTABLISHED"||seen[r.ObservationSHA256]{return errors.New("invalid monitor index receipt")}
		seen[r.ObservationSHA256]=true
		previous=r.RecordedAt
	}
	return nil
}
func readMonitorOriginal(dir string,r SourceObservationReceipt)([]byte,error){
	b,err:=readBundleArchiveFile(dir,r.ObservationSHA256+".json",MaxSourceObservationBytes)
	if err!=nil{return nil,err}
	actual,err:=verifySourceObservation(b,r.ObservationSHA256)
	if err!=nil{return nil,err}
	if actual.Source!=r.Source||actual.Mode!=r.Mode||!actual.RecordedAt.Equal(r.RecordedAt)||actual.BodySHA256!=r.BodySHA256||actual.BodyBytes!=r.BodyBytes||actual.ObservationSHA256!=r.ObservationSHA256{return nil,errors.New("monitor index receipt does not match original")}
	return b,nil
}
func readMonitorHistory(dir string,s MonitorSource,mode string)(MonitorHistory,[]byte,error){
	h:=emptyMonitorHistory(s,mode)
	if err:=monitorPrivateDir(dir);err!=nil{
		if os.IsNotExist(err){return h,nil,nil}
		return MonitorHistory{},nil,err
	}
	b,err:=readBundleArchiveFile(dir,"index.json",MaxMonitorIndexBytes)
	if os.IsNotExist(err){return h,nil,nil}
	if err!=nil{return MonitorHistory{},nil,err}
	if err:=json.Unmarshal(b,&h);err!=nil{return MonitorHistory{},nil,err}
	if err:=validateMonitorHistory(h,s,mode);err!=nil{return MonitorHistory{},nil,err}
	canonical,err:=monitorIndexBytes(h)
	if err!=nil||!bytes.Equal(canonical,b){return MonitorHistory{},nil,errors.New("noncanonical monitor index")}
	if len(h.Observations)==0{return MonitorHistory{},nil,errors.New("unexpected empty persisted monitor index")}
	latest,err:=readMonitorOriginal(dir,h.Observations[len(h.Observations)-1])
	if err!=nil{return MonitorHistory{},nil,err}
	return h,latest,nil
}

// ReadMonitorHistory reads one index and verifies its latest original. Older
// receipts remain assertions until their originals are individually replayed.
func ReadMonitorHistory(root,id,mode string)(MonitorHistory,error){
	dir,s,err:=monitorStream(root,id,mode)
	if err!=nil{return MonitorHistory{},err}
	h,_,err:=readMonitorHistory(dir,s,mode)
	return h,err
}

// VerifyMonitorRecord replays a selected indexed original. No scan or network.
func VerifyMonitorRecord(root,id,mode,pin string)(SourceObservationReceipt,error){
	if !sha256Pattern.MatchString(pin){return SourceObservationReceipt{},errors.New("independent observation pin required")}
	dir,s,err:=monitorStream(root,id,mode)
	if err!=nil{return SourceObservationReceipt{},err}
	h,latest,err:=readMonitorHistory(dir,s,mode)
	if err!=nil{return SourceObservationReceipt{},err}
	for i,r:=range h.Observations{
		if r.ObservationSHA256!=pin{continue}
		if i==len(h.Observations)-1 && latest!=nil{return r,nil}
		if _,err:=readMonitorOriginal(dir,r);err!=nil{return SourceObservationReceipt{},err}
		return r,nil
	}
	return SourceObservationReceipt{},errors.New("observation not indexed")
}

func writeMonitorIndex(dir string,b []byte)error{
	f,err:=os.CreateTemp(dir,".index-pending-")
	if err!=nil{return err}
	defer os.Remove(f.Name())
	if _,err=f.Write(b);err==nil{err=f.Sync()}
	closeErr:=f.Close();if err==nil{err=closeErr}
	if err!=nil{return err}
	return os.Rename(f.Name(),filepath.Join(dir,"index.json"))
}

// AddMonitorObservation verifies an explicit independently retained pin before
// writing. Only one cooperating writer per stream; record committed first, then
// index replaced atomically. A crash can leave an unindexed original, which an
// exact retry can reuse. No overwrite, auto-repair, history deletion or scan.
func AddMonitorObservation(root string,raw []byte,pin string)(MonitorStoreResult,error){
	r,err:=verifySourceObservation(raw,pin)
	if err!=nil{return MonitorStoreResult{},err}
	dir,s,err:=monitorStream(root,r.Source.ID,r.Mode)
	if err!=nil{return MonitorStoreResult{},err}
	if err:=os.Mkdir(dir,0700);err!=nil&&!os.IsExist(err){return MonitorStoreResult{},err}
	if err:=monitorPrivateDir(dir);err!=nil{return MonitorStoreResult{},err}
	lock:=filepath.Join(dir,".lock")
	if err:=os.Mkdir(lock,0700);err!=nil{return MonitorStoreResult{},fmt.Errorf("monitor stream locked: %w",err)}
	defer os.Remove(lock)
	h,previous,err:=readMonitorHistory(dir,s,r.Mode)
	if err!=nil{return MonitorStoreResult{},err}
	return appendMonitorObservation(dir,h,previous,raw,r)
}

// Caller must hold the stream lock and supply a verified canonical record and
// the current validated history. Shared by manual add and explicit monitor run.
func appendMonitorObservation(dir string,h MonitorHistory,previous,raw []byte,r SourceObservationReceipt)(MonitorStoreResult,error){
	pin:=r.ObservationSHA256
	result:=MonitorStoreResult{Status:"OBSERVATION_INDEXED",Observation:r,Count:len(h.Observations),TrustStatus:"NOT_ESTABLISHED"}
	for i,old:=range h.Observations{
		if old.ObservationSHA256!=pin{continue}
		if i!=len(h.Observations)-1{
			if _,err:=readMonitorOriginal(dir,old);err!=nil{return MonitorStoreResult{},err}
		}
		result.Status="EXISTING_OBSERVATION_REUSED"
		return result,nil
	}
	if len(h.Observations)>=MaxMonitorHistory{return MonitorStoreResult{},errors.New("monitor history limit; preserve existing stream and start a reviewed new store")}
	if len(h.Observations)>0{
		old:=h.Observations[len(h.Observations)-1]
		d,err:=CompareSourceObservations(previous,old.ObservationSHA256,raw,pin)
		if err!=nil{return MonitorStoreResult{},err}
		result.Diff=&d
	}
	h.Observations=append(h.Observations,r)
	b,err:=monitorIndexBytes(h)
	if err!=nil{return MonitorStoreResult{},err}
	if err:=commitArchive(dir,pin,raw);err!=nil{
		if !os.IsExist(err){return MonitorStoreResult{},err}
		existing,e:=readMonitorOriginal(dir,r)
		if e!=nil||!bytes.Equal(existing,raw){return MonitorStoreResult{},errors.New("conflicting unindexed observation")}
	}
	if err:=writeMonitorIndex(dir,b);err!=nil{return MonitorStoreResult{},err}
	result.Count=len(h.Observations)
	return result,nil
}

type MonitorPlanRow struct {
	Source MonitorSource `json:"source"`
	Attempt *MonitorAttempt `json:"attempt,omitempty"`
	Status string `json:"status"`
	Count int `json:"count"`
	Latest *SourceObservationReceipt `json:"latest,omitempty"`
	NextCheckAt *time.Time `json:"nextCheckAt,omitempty"`
	Detail string `json:"detail,omitempty"`
}
type MonitorPlan struct {
	At time.Time `json:"at"`
	IntervalSeconds int64 `json:"intervalSeconds"`
	Mode string `json:"mode"`
	Rows []MonitorPlanRow `json:"rows"`
	TrustStatus string `json:"trustStatus"`
}

// PlanMonitorChecks is read-only. It reads at most one bounded index, one
// latest original and one small HTTPS attempt record per fixed source.
func PlanMonitorChecks(root,mode string,at time.Time,interval time.Duration)(MonitorPlan,error){
	if !intakeTime(at)||interval<time.Hour||interval>30*24*time.Hour||interval%time.Second!=0{return MonitorPlan{},errors.New("explicit UTC evaluation time and whole-second interval of 1h to 30d required")}
	if mode!="HTTPS_RESPONSE"&&mode!="LOCAL_INPUT"{return MonitorPlan{},errors.New("unknown observation mode")}
	if err:=monitorPrivateDir(root);err!=nil{return MonitorPlan{},err}
	p:=MonitorPlan{At:at,IntervalSeconds:int64(interval/time.Second),Mode:mode,Rows:[]MonitorPlanRow{},TrustStatus:"NOT_ESTABLISHED"}
	for _,s:=range MonitorSources(){
		row:=MonitorPlanRow{Source:s,Status:"FIRST_OBSERVATION_REQUIRED"}
		h,err:=ReadMonitorHistory(root,s.ID,mode)
		if err!=nil{
			row.Status="LOCAL_STATE_REVIEW_REQUIRED"
			row.Detail="index or latest observation could not be verified"
		}else{
			row.Count=len(h.Observations)
			if row.Count>0{
				last:=h.Observations[row.Count-1]
				row.Latest=&last
				if last.RecordedAt.After(at){
					row.Status="LOCAL_STATE_REVIEW_REQUIRED"
					row.Detail="latest observation is in the future"
				}else if row.Count>=MaxMonitorHistory{
					row.Status="LOCAL_STATE_REVIEW_REQUIRED"
					row.Detail="history capacity reached"
				}else{
					due:=last.RecordedAt.Add(interval)
					row.NextCheckAt=&due
					row.Status="NOT_DUE_UNDER_LOCAL_POLICY"
					if !at.Before(due){row.Status="OBSERVATION_DUE"}
				}
			}
			if mode=="HTTPS_RESPONSE"&&row.Status!="LOCAL_STATE_REVIEW_REQUIRED"{
				dir,_,e:=monitorStream(root,s.ID,mode)
				var a *MonitorAttempt
				if e==nil{a,e=activeMonitorAttempt(dir,s,h,at)}
				if e!=nil{row.Status="LOCAL_STATE_REVIEW_REQUIRED";row.Detail="attempt state could not be verified";row.NextCheckAt=nil}else if a!=nil{
					row.Attempt=a
					if at.Before(a.RetryAt){row.Status="RETRY_COOLDOWN_ACTIVE";if row.NextCheckAt==nil||row.NextCheckAt.Before(a.RetryAt){row.NextCheckAt=&a.RetryAt}}
				}
			}
		}
		p.Rows=append(p.Rows,row)
	}
	return p,nil
}
