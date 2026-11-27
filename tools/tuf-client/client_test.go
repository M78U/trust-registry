package tufclient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request)(*http.Response,error)
func (f roundTrip)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}

func TestRepositoryURL(t *testing.T){
	for _,raw:=range []string{"http://example.org/m","https://user@example.org/m","https://example.org/m?secret=1","https://example.org/m/../x","https://example.org/%2e%2e/x","https://example.org/m#x"}{
		if _,err:=baseURL(raw);err==nil{t.Fatalf("accepted %s",raw)}
	}
	if got,err:=baseURL("https://example.org/metadata");err!=nil||got!="https://example.org/metadata/"{t.Fatalf("%s %v",got,err)}
}

func TestFetcherBoundary(t *testing.T){
	calls:=0
	client:=&http.Client{Transport:roundTrip(func(r *http.Request)(*http.Response,error){
		calls++
		return &http.Response{StatusCode:200,Body:io.NopCloser(strings.NewReader("abc")),ContentLength:3,Header:make(http.Header)},nil
	})}
	f:=&boundedFetcher{ctx:context.Background(),client:client,metadataBase:"https://example.org/metadata/",targetsBase:"https://example.org/targets/",remaining:12}
	for _,raw:=range []string{"https://evil.org/metadata/root.json","https://example.org/metadata/../root.json","https://example.org/metadata/other.json","https://example.org/targets/other.json","https://example.org/metadata/root.json?foo=1"}{
		if _,err:=f.DownloadFile(raw,5,time.Second);err==nil{t.Fatalf("allowed %s",raw)}
	}
	if calls!=0{t.Fatal("rejected requests reached transport")}
	if data,err:=f.DownloadFile("https://example.org/metadata/2.root.json",3,0);err!=nil||string(data)!="abc"{t.Fatalf("%s %v",data,err)}
	if _,err:=f.DownloadFile("https://example.org/targets/registry-snapshot.json",2,0);err==nil{t.Fatal("length limit ignored")}
	if _,err:=f.DownloadFile("https://example.org/targets/registry-snapshot.json",100,0);err==nil{t.Fatal("budget ignored")}
}
