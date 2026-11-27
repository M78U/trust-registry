package sources

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSHECACatalog(t *testing.T){
	c,err:=SHECA();if err!=nil{t.Fatal(err)}
	if len(c.Entries)!=17{t.Fatalf("unexpected catalog size: %d",len(c.Entries))}
	e,err:=c.Find("uca-root-historical");if err!=nil||e.PublishedStatus!="DISUSE"{t.Fatalf("historical row: %+v %v",e,err)}
	if _,err:=c.Find("missing");err==nil{t.Fatal("unknown listing accepted")}
	c.Entries[0].PublishedSHA1="invalid"
	if err:=c.Validate();err==nil{t.Fatal("invalid hash accepted")}
	again,err:=SHECA();if err!=nil||again.Entries[0].PublishedSHA1=="invalid"{t.Fatal("embedded catalog modified")}
}

func TestPreviewOnly(t *testing.T){
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	template:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic research CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
	c,err:=SHECA();if err!=nil{t.Fatal(err)}
	if _,err:=c.Preview("uca-root-g2",der,"",at);err==nil{t.Fatal("unmatched file accepted")}
	// Use a synthetic listing only in the test; never modify the embedded catalog.
	h:=sha1.Sum(der);fp:=sha256.Sum256(der)
	c.Entries[0].PublishedSHA1=hex.EncodeToString(h[:])
	result,err:=c.Preview(c.Entries[0].ID,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),hex.EncodeToString(fp[:]),at)
	if err!=nil||!result.PublishedSHA1Match||result.IndependentSHA256Status!="MATCHED_CALLER_ASSERTION"||result.Persisted||result.TrustStatus!="NOT_ESTABLISHED"||result.Provenance.ReviewStatus!="CANDIDATE"||result.Provenance.RedistributionStatus!="NOT_REVIEWED"{t.Fatalf("preview: %+v %v",result,err)}
	if _,err:=c.Preview(c.Entries[0].ID,der,strings.Repeat("a",64),at);err==nil{t.Fatal("wrong SHA256 accepted")}
}
