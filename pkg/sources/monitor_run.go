package sources

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// MonitorRunOptions authorizes one pass over explicitly selected sources.
// No scheduler, automatic retry, independent pin approval or trust update.
type MonitorRunOptions struct {
	Store string
	IDs []string
	Interval time.Duration
	MaxFetches int
}
type MonitorRunRow struct {
	Source MonitorSource `json:"source"`
	Status string `json:"status"`
	FetchAttempted bool `json:"fetchAttempted"`
	ObservationCaptured bool `json:"observationCaptured"`
	Latest *SourceObservationReceipt `json:"latest,omitempty"`
	Captured *SourceObservationReceipt `json:"captured,omitempty"`
	NextCheckAt *time.Time `json:"nextCheckAt,omitempty"`
	Stored *MonitorStoreResult `json:"stored,omitempty"`
	Attempt *MonitorAttempt `json:"attempt,omitempty"`
	PinOrigin string `json:"pinOrigin,omitempty"`
	Detail string `json:"detail,omitempty"`
}
type MonitorRunReport struct {
	StartedAt time.Time `json:"startedAt"`
	IntervalSeconds int64 `json:"intervalSeconds"`
	MaxFetches int `json:"maxFetches"`
	FetchAttempts int `json:"fetchAttempts"`
	ObservationsCaptured int `json:"observationsCaptured"`
	ObservationsIndexed int `json:"observationsIndexed"`
	Rows []MonitorRunRow `json:"rows"`
	Status string `json:"status"`
	TrustStatus string `json:"trustStatus"`
	SourceAuthentication string `json:"sourceAuthentication"`
}

func RunMonitorChecks(ctx context.Context,o MonitorRunOptions)(MonitorRunReport,error){
	if ctx==nil{return MonitorRunReport{},errors.New("context required")}
	ctx,cancel:=context.WithTimeout(ctx,5*time.Minute)
	defer cancel()
	client,closeClient:=newResearchClient()
	defer closeClient()
	return runMonitorChecks(ctx,o,client)
}
func runMonitorChecks(ctx context.Context,o MonitorRunOptions,client *http.Client)(MonitorRunReport,error){
	if ctx==nil||client==nil||len(o.IDs)==0||len(o.IDs)>len(MonitorSources())||o.MaxFetches<1||o.MaxFetches>len(o.IDs)||o.Interval<time.Hour||o.Interval>30*24*time.Hour||o.Interval%time.Second!=0{
		return MonitorRunReport{},errors.New("explicit unique sources, fetch budget and whole-second interval 1h to 30d required")
	}
	if err:=monitorPrivateDir(o.Store);err!=nil{return MonitorRunReport{},err}
	selected:=make([]MonitorSource,0,len(o.IDs))
	seen:=map[string]bool{}
	for _,id:=range o.IDs{
		s,err:=monitorSource(id)
		if err!=nil||seen[id]{return MonitorRunReport{},errors.New("invalid or duplicate monitor source ID")}
		seen[id]=true
		selected=append(selected,s)
	}
	report:=MonitorRunReport{StartedAt:time.Now().UTC(),IntervalSeconds:int64(o.Interval/time.Second),MaxFetches:o.MaxFetches,Rows:[]MonitorRunRow{},Status:"COMPLETED",TrustStatus:"NOT_ESTABLISHED",SourceAuthentication:"NOT_ESTABLISHED"}
	failed:=false
	budgetSkipped:=false
	cooldownSkipped:=false
	for _,s:=range selected{
		row:=runMonitorSource(ctx,o,s,report.FetchAttempts<o.MaxFetches,client)
		if row.FetchAttempted{report.FetchAttempts++}
		if row.ObservationCaptured{report.ObservationsCaptured++}
		if row.Stored!=nil&&row.Stored.Status=="OBSERVATION_INDEXED"{report.ObservationsIndexed++}
		switch row.Status{
		case "FETCH_BUDGET_EXHAUSTED":budgetSkipped=true
		case "RETRY_COOLDOWN_ACTIVE":cooldownSkipped=true
		case "LOCAL_STATE_REVIEW_REQUIRED","SOURCE_FETCH_FAILED","STORE_WRITE_FAILED","CANCELLED","STREAM_BUSY":failed=true
		}
		report.Rows=append(report.Rows,row)
	}
	if failed{
		report.Status="INCOMPLETE"
		return report,errors.New("one or more source checks failed or were blocked; inspect per-source report")
	}
	if budgetSkipped{report.Status="FETCH_BUDGET_REACHED"}else if cooldownSkipped{report.Status="COMPLETED_WITH_COOLDOWN"}
	return report,nil
}

func runMonitorSource(ctx context.Context,o MonitorRunOptions,s MonitorSource,allowFetch bool,client *http.Client)MonitorRunRow{
	const mode="HTTPS_RESPONSE"
	row:=MonitorRunRow{Source:s}
	fail:=func(status,detail string)MonitorRunRow{row.Status=status;row.Detail=detail;return row}
	if ctx.Err()!=nil{return fail("CANCELLED","run context ended")}
	dir,_,err:=monitorStream(o.Store,s.ID,mode)
	if err!=nil{return fail("LOCAL_STATE_REVIEW_REQUIRED","store directory unavailable")}
	// Budget-exhausted rows are diagnostic only, never create or lock a stream.
	if !allowFetch{
		h,_,err:=readMonitorHistory(dir,s,mode)
		if err!=nil{return fail("LOCAL_STATE_REVIEW_REQUIRED","index or latest observation could not be verified")}
		if due,_:=monitorRunEligible(&row,dir,h,time.Now().UTC(),o.Interval);due{row.Status="FETCH_BUDGET_EXHAUSTED"}
		return row
	}
	if err:=os.Mkdir(dir,0700);err!=nil&&!os.IsExist(err){return fail("LOCAL_STATE_REVIEW_REQUIRED","cannot create private source stream")}
	if err:=monitorPrivateDir(dir);err!=nil{return fail("LOCAL_STATE_REVIEW_REQUIRED","source stream is not private")}
	lock:=filepath.Join(dir,".lock")
	if err:=os.Mkdir(lock,0700);err!=nil{
		if os.IsExist(err){return fail("STREAM_BUSY","source stream is locked")}
		return fail("LOCAL_STATE_REVIEW_REQUIRED","cannot acquire source stream lock")
	}
	defer os.Remove(lock)
	h,previous,err:=readMonitorHistory(dir,s,mode)
	if err!=nil{return fail("LOCAL_STATE_REVIEW_REQUIRED","index or latest observation could not be verified")}
	at:=time.Now().UTC()
	dueNow,prior:=monitorRunEligible(&row,dir,h,at,o.Interval)
	if !dueNow{return row}
	if ctx.Err()!=nil{return fail("CANCELLED","run context ended before request")}
	a:=newMonitorAttempt(s,h,prior,at)
	if err:=writeMonitorAttempt(dir,a);err!=nil{return fail("STORE_WRITE_FAILED","cannot persist pre-request cooldown; no request made")}
	row.Attempt=&a
	row.NextCheckAt=&a.RetryAt
	finishFailure:=func(status,detail string)MonitorRunRow{
		updated:=a;updated.Outcome=status
		if err:=writeMonitorAttempt(dir,updated);err!=nil{return fail("STORE_WRITE_FAILED","failure outcome could not be saved; pre-request cooldown remains")}
		row.Attempt=&updated
		return fail(status,detail)
	}
	if ctx.Err()!=nil{return finishFailure("CANCELLED","run context ended after attempt reservation")}
	row.FetchAttempted=true
	raw,r,err:=fetchSourceObservation(ctx,client,s.ID)
	if err!=nil{
		if ctx.Err()!=nil{return finishFailure("CANCELLED","run context ended during request")}
		return finishFailure("SOURCE_FETCH_FAILED",err.Error())
	}
	row.ObservationCaptured=true
	row.Captured=&r
	row.PinOrigin="LOCAL_CAPTURE_DIGEST_NOT_INDEPENDENTLY_REVIEWED"
	verified,err:=verifySourceObservation(raw,r.ObservationSHA256)
	if err!=nil||verified.Source!=s||verified.Mode!=mode||!verified.RecordedAt.After(a.StartedAt){return finishFailure("STORE_WRITE_FAILED","captured observation did not replay or clock did not advance")}
	if ctx.Err()!=nil{return finishFailure("CANCELLED","run context ended before storage")}
	// Hold the same lock from due check through commit: other cooperating
	// runs and manual adds cannot interleave a fetch with a new baseline.
	stored,err:=appendMonitorObservation(dir,h,previous,raw,verified)
	if err!=nil{return finishFailure("STORE_WRITE_FAILED","observation append failed; inspect local store before retry")}
	row.Stored=&stored
	// The committed newer observation supersedes the reservation. No second
	// success-state write or removal is required (including after a crash).
	row.Attempt=nil
	row.Status="BASELINE_CAPTURED"
	if stored.Diff!=nil{row.Status=stored.Diff.Status}
	due:=verified.RecordedAt.Add(o.Interval)
	row.NextCheckAt=&due
	return row
}

// Decide using the latest verified original only, not the last failed attempt.
func monitorRunDue(row *MonitorRunRow,h MonitorHistory,at time.Time,interval time.Duration)bool{
	if len(h.Observations)==0{return true}
	last:=h.Observations[len(h.Observations)-1]
	row.Latest=&last
	if last.RecordedAt.After(at)||len(h.Observations)>=MaxMonitorHistory{
		row.Status="LOCAL_STATE_REVIEW_REQUIRED"
		row.Detail="future observation or history capacity reached"
		return false
	}
	due:=last.RecordedAt.Add(interval)
	row.NextCheckAt=&due
	if at.Before(due){
		row.Status="NOT_DUE_UNDER_LOCAL_POLICY"
		return false
	}
	return true
}


// Keep planning and execution aligned on the same persisted cooldown state.
func monitorRunEligible(row *MonitorRunRow,dir string,h MonitorHistory,at time.Time,interval time.Duration)(bool,*MonitorAttempt){
	due:=monitorRunDue(row,h,at,interval)
	if row.Status=="LOCAL_STATE_REVIEW_REQUIRED"{return false,nil}
	a,err:=activeMonitorAttempt(dir,row.Source,h,at)
	if err!=nil{
		row.Status="LOCAL_STATE_REVIEW_REQUIRED"
		row.Detail="attempt state could not be verified"
		row.NextCheckAt=nil
		return false,nil
	}
	if a!=nil{
		row.Attempt=a
		if at.Before(a.RetryAt){
			row.Status="RETRY_COOLDOWN_ACTIVE"
			if row.NextCheckAt==nil||row.NextCheckAt.Before(a.RetryAt){row.NextCheckAt=&a.RetryAt}
			return false,a
		}
	}
	return due,a
}
