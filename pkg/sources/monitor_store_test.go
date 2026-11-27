package sources

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMonitorStoreHistory(t *testing.T){
	root:=t.TempDir()
	if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
	at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
	a,ar,err:=ObserveLocalSource("sheca-repository",[]byte("one"),at)
	if err!=nil{t.Fatal(err)}
	b,br,err:=ObserveLocalSource("sheca-repository",[]byte("two"),at.Add(time.Hour))
	if err!=nil{t.Fatal(err)}
	if _,err:=AddMonitorObservation(root,a,br.ObservationSHA256);err==nil{t.Fatal("wrong pin")}
	if entries,err:=os.ReadDir(root);err!=nil||len(entries)!=0{t.Fatal(entries,err)}
	p,err:=PlanMonitorChecks(root,"LOCAL_INPUT",at,time.Hour)
	if err!=nil||len(p.Rows)!=8{t.Fatal(p,err)}
	for _,r:=range p.Rows{if r.Status!="FIRST_OBSERVATION_REQUIRED"{t.Fatal(r)}}
	if entries,err:=os.ReadDir(root);err!=nil||len(entries)!=0{t.Fatal("plan wrote state",entries,err)}
	r,err:=AddMonitorObservation(root,a,ar.ObservationSHA256)
	if err!=nil||r.Count!=1||r.Diff!=nil{t.Fatal(r,err)}
	r,err=AddMonitorObservation(root,b,br.ObservationSHA256)
	if err!=nil||r.Count!=2||r.Diff==nil||!r.Diff.ReviewSuggested{t.Fatal(r,err)}
	r,err=AddMonitorObservation(root,a,ar.ObservationSHA256)
	if err!=nil||r.Count!=2||r.Status!="EXISTING_OBSERVATION_REUSED"{t.Fatal(r,err)}
	old,oldr,err:=ObserveLocalSource("sheca-repository",[]byte("old"),at.Add(-time.Hour))
	if err!=nil{t.Fatal(err)}
	if _,err:=AddMonitorObservation(root,old,oldr.ObservationSHA256);err==nil{t.Fatal("backdated append")}
	h,err:=ReadMonitorHistory(root,"sheca-repository","LOCAL_INPUT")
	if err!=nil||len(h.Observations)!=2{t.Fatal(h,err)}
	h,err=ReadMonitorHistory(root,"sheca-repository","HTTPS_RESPONSE")
	if err!=nil||len(h.Observations)!=0{t.Fatal("mixed modes",h,err)}
	if _,err:=VerifyMonitorRecord(root,"sheca-repository","LOCAL_INPUT",ar.ObservationSHA256);err!=nil{t.Fatal(err)}
	for _,c:=range []struct{at time.Time;status string}{
		{at,"LOCAL_STATE_REVIEW_REQUIRED"},
		{at.Add(time.Hour),"NOT_DUE_UNDER_LOCAL_POLICY"},
		{at.Add(2*time.Hour),"OBSERVATION_DUE"},
	}{
		p,err:=PlanMonitorChecks(root,"LOCAL_INPUT",c.at,time.Hour)
		if err!=nil{t.Fatal(err)}
		found:=false
		for _,row:=range p.Rows{if row.Source.ID=="sheca-repository"{found=true;if row.Status!=c.status{t.Fatal(row)}}}
		if !found{t.Fatal("missing source")}
	}
	dir:=filepath.Join(root,"sheca-repository-LOCAL_INPUT")
	if err:=os.Mkdir(filepath.Join(dir,".lock"),0700);err!=nil{t.Fatal(err)}
	if _,err:=AddMonitorObservation(root,b,br.ObservationSHA256);err==nil{t.Fatal("lock bypass")}
	if err:=os.Remove(filepath.Join(dir,".lock"));err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(filepath.Join(dir,br.ObservationSHA256+".json"),[]byte("corrupt"),0600);err!=nil{t.Fatal(err)}
	if _,err:=ReadMonitorHistory(root,"sheca-repository","LOCAL_INPUT");err==nil{t.Fatal("corrupt latest accepted")}
	p,err=PlanMonitorChecks(root,"LOCAL_INPUT",at.Add(2*time.Hour),time.Hour)
	if err!=nil{t.Fatal(err)}
	for _,row:=range p.Rows{if row.Source.ID=="sheca-repository"&&row.Status!="LOCAL_STATE_REVIEW_REQUIRED"{t.Fatal(row)}}
}

func TestMonitorStoreUnindexedRetry(t *testing.T){
	root:=t.TempDir()
	if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
	at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
	b,r,err:=ObserveLocalSource("satl-list",[]byte("catalog"),at)
	if err!=nil{t.Fatal(err)}
	dir:=filepath.Join(root,"satl-list-LOCAL_INPUT")
	if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
	if err:=commitArchive(dir,r.ObservationSHA256,b);err!=nil{t.Fatal(err)}
	h,err:=ReadMonitorHistory(root,"satl-list","LOCAL_INPUT")
	if err!=nil||len(h.Observations)!=0{t.Fatal(h,err)}
	result,err:=AddMonitorObservation(root,b,r.ObservationSHA256)
	if err!=nil||result.Count!=1{t.Fatal(result,err)}
	if err:=os.WriteFile(filepath.Join(dir,"index.json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	if _,err:=AddMonitorObservation(root,b,r.ObservationSHA256);err==nil{t.Fatal("corrupt index replaced")}
}
