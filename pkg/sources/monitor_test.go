package sources

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSourceObservationDiff(t *testing.T) {
	at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
	first,a,err:=ObserveLocalSource("sheca-repository",[]byte("one"),at)
	if err!=nil{t.Fatal(err)}
	second,b,err:=ObserveLocalSource("sheca-repository",[]byte("two"),at.Add(time.Hour))
	if err!=nil{t.Fatal(err)}
	d,err:=CompareSourceObservations(first,a.ObservationSHA256,second,b.ObservationSHA256)
	if err!=nil||!d.ReviewSuggested||d.Status!="BODY_CHANGED_REVIEW_REQUIRED"||d.SemanticChange!="NOT_EVALUATED"||d.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(d,err)}
	same,c,err:=ObserveLocalSource("sheca-repository",[]byte("one"),at.Add(time.Hour))
	if err!=nil{t.Fatal(err)}
	d,err=CompareSourceObservations(first,a.ObservationSHA256,same,c.ObservationSHA256)
	if err!=nil||d.ReviewSuggested||d.Status!="BODY_UNCHANGED"{t.Fatal(d,err)}
	if _,err:=CompareSourceObservations(first,a.ObservationSHA256,second,a.ObservationSHA256);err==nil{t.Fatal("wrong pin")}
	tampered:=bytes.Replace(second,[]byte("NOT_ESTABLISHED"),[]byte("TRUSTED"),1)
	if _,err:=CompareSourceObservations(first,a.ObservationSHA256,tampered,intakeHash(tampered));err==nil{t.Fatal("forged trust accepted")}
	if _,err:=CompareSourceObservations(second,b.ObservationSHA256,first,a.ObservationSHA256);err==nil{t.Fatal("backward time")}
	other,e,err:=ObserveLocalSource("satl-list",[]byte("two"),at.Add(time.Hour))
	if err!=nil{t.Fatal(err)}
	if _,err:=CompareSourceObservations(first,a.ObservationSHA256,other,e.ObservationSHA256);err==nil{t.Fatal("different source")}
	if _,_,err:=ObserveLocalSource("unknown",[]byte("x"),at);err==nil{t.Fatal("unknown source")}
	if _,_,err:=ObserveLocalSource("sheca-repository",make([]byte,MaxSourceBodyBytes+1),at);err==nil{t.Fatal("oversize")}
}

type monitorRoundTrip func(*http.Request)(*http.Response,error)
func(f monitorRoundTrip)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}
func TestMonitorFetchBoundaries(t *testing.T){
	calls:=0
	status:=200
	body:="catalog"
	media:="text/html; charset=utf-8"
	encoding:=""
	client:=&http.Client{Transport:monitorRoundTrip(func(r *http.Request)(*http.Response,error){
		calls++
		if r.Method!="GET"||r.URL.String()!="https://www.sheca.com/repository"{t.Fatal(r.Method,r.URL)}
		return &http.Response{StatusCode:status,Header:http.Header{"Content-Type":{media},"Content-Encoding":{encoding}},Body:io.NopCloser(strings.NewReader(body)),ContentLength:-1},nil
	})}
	raw,r,err:=fetchSourceObservation(context.Background(),client,"sheca-repository")
	if err!=nil||calls!=1||r.Mode!="HTTPS_RESPONSE"||r.BodySHA256!=intakeHash([]byte(body)){t.Fatal(r,err,calls)}
	if _,err:=verifySourceObservation(raw,r.ObservationSHA256);err!=nil{t.Fatal(err)}
	if _,_,err:=fetchSourceObservation(context.Background(),client,"https://example.org");err==nil||calls!=1{t.Fatal("unexpected arbitrary fetch")}
	for _,bad:=range []struct{status int;body,media,encoding string}{
		{404,"error","text/html",""},{200,"","text/html",""},{200,"x","application/octet-stream",""},{200,"x","text/html","gzip"},{200,strings.Repeat("x",MaxSourceBodyBytes+1),"text/html",""},
	}{
		status,body,media,encoding=bad.status,bad.body,bad.media,bad.encoding
		if _,_,err:=fetchSourceObservation(context.Background(),client,"sheca-repository");err==nil{t.Fatal("bad response accepted")}
	}
}
