package sources

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMonitorAttemptBackoffAndBoundaries(t *testing.T){
	s,err:=monitorSource("satl-list");if err!=nil{t.Fatal(err)}
	at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
	h:=emptyMonitorHistory(s,"HTTPS_RESPONSE")
	var prior *MonitorAttempt
	for i,hours:=range []int{1,2,4,8,16,24,24}{
		a:=newMonitorAttempt(s,h,prior,at)
		if err:=validateMonitorAttempt(a,s);err!=nil{t.Fatal(err)}
		if !a.RetryAt.Equal(at.Add(time.Duration(hours)*time.Hour)){t.Fatal(i,a)}
		prior=&a
		at=a.RetryAt
	}
	dir:=t.TempDir()
	a:=newMonitorAttempt(s,h,nil,at)
	if err:=writeMonitorAttempt(dir,a);err!=nil{t.Fatal(err)}
	row:=MonitorRunRow{Source:s}
	if ok,_:=monitorRunEligible(&row,dir,h,a.RetryAt.Add(-time.Nanosecond),time.Hour);ok||row.Status!="RETRY_COOLDOWN_ACTIVE"{t.Fatal(row)}
	row=MonitorRunRow{Source:s}
	if ok,prior:=monitorRunEligible(&row,dir,h,a.RetryAt,time.Hour);!ok||prior==nil{t.Fatal(row,prior)}
	row=MonitorRunRow{Source:s}
	if ok,_:=monitorRunEligible(&row,dir,h,a.StartedAt.Add(-time.Second),time.Hour);ok||row.Status!="LOCAL_STATE_REVIEW_REQUIRED"{t.Fatal(row)}
}

func TestMonitorAttemptCrashAndCorruptState(t *testing.T){
	root:=t.TempDir()
	if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
	s,err:=monitorSource("sheca-repository");if err!=nil{t.Fatal(err)}
	dir:=filepath.Join(root,s.ID+"-HTTPS_RESPONSE")
	if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
	a:=newMonitorAttempt(s,emptyMonitorHistory(s,"HTTPS_RESPONSE"),nil,time.Now().UTC())
	if err:=writeMonitorAttempt(dir,a);err!=nil{t.Fatal(err)}
	calls:=0
	client:=&http.Client{Transport:monitorRoundTrip(func(*http.Request)(*http.Response,error){
		calls++
		return &http.Response{StatusCode:503,Header:http.Header{"Content-Type":{"text/html"}},Body:io.NopCloser(strings.NewReader("error")),ContentLength:-1},nil
	})}
	o:=MonitorRunOptions{Store:root,IDs:[]string{s.ID},Interval:time.Hour,MaxFetches:1}
	r,err:=runMonitorChecks(context.Background(),o,client)
	if err!=nil||calls!=0||r.Rows[0].Status!="RETRY_COOLDOWN_ACTIVE"||r.Rows[0].Attempt.Outcome!="ATTEMPT_UNCONFIRMED"{t.Fatal(r,err,calls)}
	if err:=os.WriteFile(filepath.Join(dir,monitorAttemptFile),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	r,err=runMonitorChecks(context.Background(),o,client)
	if err==nil||calls!=0||r.Rows[0].Status!="LOCAL_STATE_REVIEW_REQUIRED"{t.Fatal(r,err,calls)}
}
