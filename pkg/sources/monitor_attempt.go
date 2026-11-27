package sources

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const maxMonitorAttemptBytes=4096
const maxMonitorFailureStreak=6
const monitorAttemptFile="attempt.json"

// MonitorAttempt is a bounded local operational record, not source evidence.
// Persist before a GET: even a crash or cancelled request consumes cooldown.
// A newer verified successful observation supersedes this record.
type MonitorAttempt struct {
	SchemaVersion string `json:"schemaVersion"`
	Source MonitorSource `json:"source"`
	StartedAt time.Time `json:"startedAt"`
	RetryAt time.Time `json:"retryAt"`
	ConsecutiveAttempts int `json:"consecutiveAttempts"`
	BaselineSHA256 string `json:"baselineSHA256,omitempty"`
	Outcome string `json:"outcome"`
}

func monitorCooldown(n int)time.Duration{
	if n>=maxMonitorFailureStreak{return 24*time.Hour}
	return time.Hour*time.Duration(1<<uint(n-1))
}

func newMonitorAttempt(s MonitorSource,h MonitorHistory,prior *MonitorAttempt,at time.Time)MonitorAttempt{
	n:=1
	if prior!=nil{
		n=prior.ConsecutiveAttempts+1
		if n>maxMonitorFailureStreak{n=maxMonitorFailureStreak}
	}
	a:=MonitorAttempt{SchemaVersion:"1",Source:s,StartedAt:at,RetryAt:at.Add(monitorCooldown(n)),ConsecutiveAttempts:n,Outcome:"ATTEMPT_UNCONFIRMED"}
	if len(h.Observations)>0{a.BaselineSHA256=h.Observations[len(h.Observations)-1].ObservationSHA256}
	return a
}

func monitorAttemptBytes(a MonitorAttempt)([]byte,error){
	b,err:=json.Marshal(a)
	if err!=nil{return nil,err}
	b=append(b,'\n')
	if len(b)>maxMonitorAttemptBytes{return nil,errors.New("monitor attempt size limit")}
	return b,nil
}

func validateMonitorAttempt(a MonitorAttempt,s MonitorSource)error{
	if a.SchemaVersion!="1"||a.Source!=s||!intakeTime(a.StartedAt)||!intakeTime(a.RetryAt)||a.ConsecutiveAttempts<1||a.ConsecutiveAttempts>maxMonitorFailureStreak||!a.RetryAt.Equal(a.StartedAt.Add(monitorCooldown(a.ConsecutiveAttempts)))||a.BaselineSHA256!=""&&!sha256Pattern.MatchString(a.BaselineSHA256){
		return errors.New("invalid monitor attempt state")
	}
	switch a.Outcome{
	case "ATTEMPT_UNCONFIRMED","SOURCE_FETCH_FAILED","CANCELLED","STORE_WRITE_FAILED":
		return nil
	default:return errors.New("invalid monitor attempt outcome")
	}
}

// activeMonitorAttempt reads a single fixed file. A successful observation
// must be later than the attempt start and not the attempt's prior baseline.
// Missing/deleted state cannot be distinguished from a never-attempted source.
func activeMonitorAttempt(dir string,s MonitorSource,h MonitorHistory,at time.Time)(*MonitorAttempt,error){
	b,err:=readBundleArchiveFile(dir,monitorAttemptFile,maxMonitorAttemptBytes)
	if os.IsNotExist(err){return nil,nil}
	if err!=nil{return nil,err}
	var a MonitorAttempt
	if err:=json.Unmarshal(b,&a);err!=nil{return nil,err}
	if err:=validateMonitorAttempt(a,s);err!=nil{return nil,err}
	canonical,err:=monitorAttemptBytes(a)
	if err!=nil||!bytes.Equal(b,canonical){return nil,errors.New("noncanonical monitor attempt state")}
	if a.StartedAt.After(at){return nil,errors.New("monitor attempt is in the future")}
	if len(h.Observations)>0{
		last:=h.Observations[len(h.Observations)-1]
		if last.ObservationSHA256!=a.BaselineSHA256 && last.RecordedAt.After(a.StartedAt){
			return nil,nil
		}
	}
	if a.BaselineSHA256!=""{
		// Detect a lost or rolled back baseline when possible; this is
		// operational consistency, not authenticated rollback protection.
		found:=false
		for _,r:=range h.Observations{if r.ObservationSHA256==a.BaselineSHA256{found=true;break}}
		if !found{return nil,errors.New("monitor attempt baseline not indexed")}
	}
	return &a,nil
}

// writeMonitorAttempt requires the existing per-stream writer lock. Replaces
// only the small operational state, never an original or history index.
func writeMonitorAttempt(dir string,a MonitorAttempt)error{
	if err:=validateMonitorAttempt(a,a.Source);err!=nil{return err}
	b,err:=monitorAttemptBytes(a)
	if err!=nil{return err}
	f,err:=os.CreateTemp(dir,".attempt-pending-")
	if err!=nil{return err}
	defer os.Remove(f.Name())
	if _,err=f.Write(b);err==nil{err=f.Sync()}
	closeErr:=f.Close();if err==nil{err=closeErr}
	if err!=nil{return err}
	return os.Rename(f.Name(),filepath.Join(dir,monitorAttemptFile))
}
