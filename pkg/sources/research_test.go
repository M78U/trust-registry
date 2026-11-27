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
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestResearchPartialAndLegacy(t *testing.T){
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	tmpl:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic research batch CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,tmpl,tmpl,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
	c,err:=SHECA();if err!=nil{t.Fatal(err)}
	e,err:=Endpoints();if err!=nil{t.Fatal(err)}
	// First endpoint becomes a synthetic SHA-256 lead. Second returns HTTP
	// 404. Third has no SHA-256 and must not be fetched by default.
	sum:=sha1.Sum(der);fp:=sha256.Sum256(der)
	c.Entries[0].PublishedSHA1=hex.EncodeToString(sum[:])
	e[0].PublishedSHA256=&FingerprintEvidence{hex.EncodeToString(fp[:]),"https://example.org/claim","SYNTHETIC"}
	e[2].PublishedSHA256=nil
	calls:=0
	client:=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
		calls++
		if req.URL.String()==e[0].DownloadURL{return &http.Response{StatusCode:200,Body:io.NopCloser(bytes.NewReader(der)),ContentLength:int64(len(der)),Header:make(http.Header)},nil}
		return &http.Response{StatusCode:404,Body:io.NopCloser(strings.NewReader("not found")),Header:make(http.Header)},nil
	})}
	r,err:=research(context.Background(),client,c,e[:3],false)
	if err==nil||r.Attempted!=2||r.Succeeded!=1||r.Failed!=1||r.Skipped!=1||calls!=2||r.TrustStatus!="NOT_ESTABLISHED"||r.RegistryImported||r.OriginalFilesSaved{t.Fatalf("partial report: %+v %v",r,err)}
	if r.Items[0].Report==nil||r.Items[0].Report.OriginalFileSaved||r.Items[1].Error==""||r.Items[2].Status!="SKIPPED_NO_SHA256_LEAD"{t.Fatal("unexpected report states")}
	out,err:=json.Marshal(r);if err!=nil||bytes.Contains(out,[]byte("BEGIN CERTIFICATE")){t.Fatal("invalid report")}
	calls=0
	r,err=research(context.Background(),client,c,e[:3],true)
	if err==nil||r.Attempted!=3||r.Failed!=2||r.Skipped!=0||calls!=3{t.Fatalf("legacy opt-in: %+v %v",r,err)}
	ctx,cancel:=context.WithCancel(context.Background());cancel()
	calls=0
	r,err=research(ctx,client,c,e[:3],false)
	if err==nil||calls!=0||r.Attempted!=0||r.Skipped!=3{t.Fatalf("cancel: %+v %v",r,err)}
}
