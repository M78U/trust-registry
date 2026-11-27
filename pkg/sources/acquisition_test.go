package sources

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request)(*http.Response,error)
func (f roundTripFunc)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}

func TestObservedEndpoints(t *testing.T){
	e,err:=Endpoints();if err!=nil{t.Fatal(err)}
	if len(e)!=11{t.Fatalf("endpoints: %d",len(e))}
	count:=0
	for _,v:=range e{if v.PublishedSHA256!=nil{count++}}
	if count!=3{t.Fatalf("published SHA256 count: %d",count)}
	if _,err:=findEndpoint("sheca-g2");err==nil{t.Fatal("unobserved endpoint accepted")}
	if _,err:=Fetch(context.Background(),"uca-root-g2","unused",false);err==nil{t.Fatal("legacy-only fetch allowed without consent")}
}

func TestAcquisitionChecks(t *testing.T){
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	template:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic acquisition CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
	c,err:=SHECA();if err!=nil{t.Fatal(err)}
	e,err:=findEndpoint("uca-root-g2");if err!=nil{t.Fatal(err)}
	h:=sha1.Sum(der);fp:=sha256.Sum256(der)
	c.Entries[0].PublishedSHA1=hex.EncodeToString(h[:])
	e.PublishedSHA256=&FingerprintEvidence{hex.EncodeToString(fp[:]),"https://example.org/evidence","SYNTHETIC"}
	client:=&http.Client{Transport:roundTripFunc(func(r *http.Request)(*http.Response,error){
		if r.URL.String()!=e.DownloadURL||r.Method!="GET"{t.Fatal("unexpected request")}
		return &http.Response{StatusCode:200,Body:io.NopCloser(bytes.NewReader(der)),ContentLength:int64(len(der)),Header:make(http.Header)},nil
	})}
	got,report,err:=fetchBytes(context.Background(),client,c,e,false)
	if err!=nil||!bytes.Equal(got,der)||report.PublishedSHA256Status!="MATCHED_PUBLISHED_FINGERPRINT"||report.Analysis.SelfSignatureStatus!="VERIFIED"||report.TrustStatus!="NOT_ESTABLISHED"||report.RegistryImported||report.OriginalFileSaved||report.Preview.Provenance.SourceURL!=e.DownloadURL{t.Fatalf("acquisition: %+v %v",report,err)}
	e.PublishedSHA256.Fingerprint=strings.Repeat("a",64)
	if _,_,err:=fetchBytes(context.Background(),client,c,e,false);err==nil{t.Fatal("wrong SHA256 accepted")}
	e.PublishedSHA256=nil
	if _,_,err:=fetchBytes(context.Background(),client,c,e,false);err==nil{t.Fatal("legacy-only accepted")}
	for _,code:=range []int{301,404}{
		other:=&http.Client{Transport:roundTripFunc(func(*http.Request)(*http.Response,error){return &http.Response{StatusCode:code,Body:io.NopCloser(strings.NewReader("error")),Header:make(http.Header)},nil})}
		if _,_,err:=fetchBytes(context.Background(),other,c,e,true);err==nil{t.Fatal("invalid HTTP status accepted")}
	}
}
