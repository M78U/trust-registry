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

func TestMonitorRunBudgetAndFreshness(t *testing.T){
	root:=t.TempDir()
	if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
	calls:=0
	client:=&http.Client{Transport:monitorRoundTrip(func(r *http.Request)(*http.Response,error){
		calls++
		return &http.Response{StatusCode:200,Header:http.Header{"Content-Type":{"text/html"}},Body:io.NopCloser(strings.NewReader("catalog")),ContentLength:-1},nil
	})}
	o:=MonitorRunOptions{Store:root,IDs:[]string{"sheca-repository","satl-list"},Interval:time.Hour,MaxFetches:1}
	bad:=o;bad.IDs=[]string{"sheca-repository","sheca-repository"}
	if _,err:=runMonitorChecks(context.Background(),bad,client);err==nil||calls!=0{t.Fatal("duplicate selection made requests")}
	r,err:=runMonitorChecks(context.Background(),o,client)
	if err!=nil||calls!=1||r.FetchAttempts!=1||r.ObservationsIndexed!=1||r.Status!="FETCH_BUDGET_REACHED"||r.Rows[0].Status!="BASELINE_CAPTURED"||r.Rows[1].Status!="FETCH_BUDGET_EXHAUSTED"||r.Rows[0].PinOrigin!="LOCAL_CAPTURE_DIGEST_NOT_INDEPENDENTLY_REVIEWED"{t.Fatal(r,err,calls)}
	if _,err:=os.Stat(filepath.Join(root,"satl-list-HTTPS_RESPONSE"));!os.IsNotExist(err){t.Fatal("budget skip created stream",err)}
	r,err=runMonitorChecks(context.Background(),o,client)
	if err!=nil||calls!=2||r.Rows[0].Status!="NOT_DUE_UNDER_LOCAL_POLICY"||r.Rows[1].Status!="BASELINE_CAPTURED"{t.Fatal(r,err,calls)}
	r,err=runMonitorChecks(context.Background(),o,client)
	if err!=nil||calls!=2||r.FetchAttempts!=0||r.ObservationsIndexed!=0{t.Fatal(r,err,calls)}
}
func TestMonitorRunFailureAndLock(t *testing.T){
	root:=t.TempDir()
	if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
	at:=time.Now().UTC().Add(-2*time.Hour)
	raw,receipt,err:=makeSourceObservation("sheca-repository","HTTPS_RESPONSE","text/html",[]byte("old"),at)
	if err!=nil{t.Fatal(err)}
	if _,err:=AddMonitorObservation(root,raw,receipt.ObservationSHA256);err!=nil{t.Fatal(err)}
	dir:=filepath.Join(root,"sheca-repository-HTTPS_RESPONSE")
	lock:=filepath.Join(dir,".lock")
	calls:=0
	status:=503
	client:=&http.Client{Transport:monitorRoundTrip(func(r *http.Request)(*http.Response,error){
		calls++
		if _,err:=os.Stat(lock);err!=nil{t.Fatal("lock not held during request",err)}
		// A cooperating writer must be unable to interleave with this request.
		if _,err:=AddMonitorObservation(root,raw,receipt.ObservationSHA256);err==nil{t.Fatal("interleaved writer")}
		return &http.Response{StatusCode:status,Header:http.Header{"Content-Type":{"text/html"}},Body:io.NopCloser(strings.NewReader("new")),ContentLength:-1},nil
	})}
	o:=MonitorRunOptions{Store:root,IDs:[]string{"sheca-repository"},Interval:time.Hour,MaxFetches:1}
	if err:=os.Mkdir(lock,0700);err!=nil{t.Fatal(err)}
	r,err:=runMonitorChecks(context.Background(),o,client)
	if err==nil||calls!=0||r.Rows[0].Status!="STREAM_BUSY"{t.Fatal(r,err,calls)}
	if err:=os.Remove(lock);err!=nil{t.Fatal(err)}
	r,err=runMonitorChecks(context.Background(),o,client)
	if err==nil||calls!=1||r.Rows[0].Status!="SOURCE_FETCH_FAILED"||r.ObservationsIndexed!=0{t.Fatal(r,err,calls)}
	h,err:=ReadMonitorHistory(root,"sheca-repository","HTTPS_RESPONSE")
	if err!=nil||len(h.Observations)!=1||h.Observations[0].ObservationSHA256!=receipt.ObservationSHA256{t.Fatal(h,err)}
	status=200
	r,err=runMonitorChecks(context.Background(),o,client)
	if err!=nil||calls!=2||r.Rows[0].Status!="BODY_CHANGED_REVIEW_REQUIRED"||r.ObservationsIndexed!=1{t.Fatal(r,err,calls)}
	ctx,cancel:=context.WithCancel(context.Background());cancel()
	r,err=runMonitorChecks(ctx,o,client)
	if err==nil||calls!=2||r.Rows[0].Status!="CANCELLED"{t.Fatal(r,err,calls)}
}
