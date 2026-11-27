package sources

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
)

func TestAcquisitionCoverageCatalog(t *testing.T){
	s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
	if _,err:=PlanAcquisitionCoverage(s);err==nil{t.Fatal("uninitialized inventory accepted")}
	if _,err:=s.Init();err!=nil{t.Fatal(err)}
	r,err:=PlanAcquisitionCoverage(s);if err!=nil{t.Fatal(err)}
	if r.Counts!=(AcquisitionCoverageCounts{ListingRows:32,ExactFingerprintRows:8,MissingInventoryRows:8,NoExactFingerprintRows:24})||r.TrustStatus!="NOT_ESTABLISHED"||r.SourceAuthentication!="NOT_ESTABLISHED"||r.ReleaseAuthenticated{t.Fatal(r)}
	want:=map[string]int{"PINNED_ENDPOINT_ARCHIVE":3,"EXPLICIT_LEGACY_ONLY_RESEARCH":8,"RESEARCH_DOWNLOAD_ENDPOINT":6,"MANUAL_CHAIN_BUNDLE_RESEARCH":7,"RESEARCH_OFFICIAL_SOURCE":3,"RESEARCH_EXACT_FINGERPRINT":3,"PINNED_SINGLE_CERTIFICATE_ARCHIVE":2}
	for k,v:=range want{if r.RouteCounts[k]!=v{t.Fatal(k,r.RouteCounts)}}
	if len(r.RouteCounts)!=len(want){t.Fatal(r.RouteCounts)}
	last:=""
	for _,v:=range r.Tasks{
		key:=v.Authority+"/"+v.ListingID
		if key<=last||v.ArchiveStatus!="NOT_CHECKED"||v.RedistributionStatus!="NOT_REVIEWED"||v.MatchingSourceAssertions!=0{t.Fatal(v)}
		last=key
	}
	again,err:=PlanAcquisitionCoverage(s);if err!=nil{t.Fatal(err)}
	a,err:=json.Marshal(r);if err!=nil{t.Fatal(err)}
	b,err:=json.Marshal(again);if err!=nil||!bytes.Equal(a,b){t.Fatal("non-deterministic report",err)}
}

func TestAcquisitionCoverageExactSourceAssertion(t *testing.T){
	c,err:=SHECA();if err!=nil{t.Fatal(err)}
	e,err:=Endpoints();if err!=nil{t.Fatal(err)}
	m,err:=MultiCA();if err!=nil{t.Fatal(err)}
	at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	tpl:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,tpl,tpl,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
	id:="uca-global-g2"
	var source string
	for n:=range e{if e[n].ListingID==id{
		v:=*e[n].PublishedSHA256;v.Fingerprint=intakeHash(der);e[n].PublishedSHA256=&v;source=e[n].DownloadURL
	}}
	if source==""{t.Fatal("missing fixture endpoint")}
	s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
	if _,err:=s.Init();err!=nil{t.Fatal(err)}
	if _,err:=s.Import(der,source+".other",at);err!=nil{t.Fatal(err)}
	check:=func(want int){
		t.Helper()
		index,err:=s.BuildIndex();if err!=nil{t.Fatal(err)}
		r,err:=acquisitionCoverage(c,e,m,index);if err!=nil{t.Fatal(err)}
		if r.Counts.MatchingInventoryRows!=1||r.Counts.MissingInventoryRows!=7||r.Counts.MatchingSourceAssertionRows!=want||r.ReleaseAuthenticated{t.Fatal(r.Counts)}
		for _,v:=range r.Tasks{if v.ListingID==id{
			if v.InventoryStatus!="EXACT_FINGERPRINT_PRESENT"||v.MatchingSourceAssertions!=want||v.ArchiveStatus!="NOT_CHECKED"||v.AcquisitionRoute!="PINNED_ENDPOINT_ARCHIVE"{t.Fatal(v)}
			return
		}}
		t.Fatal("missing task")
	}
	check(0)
	if _,err:=s.Import(der,source,at);err!=nil{t.Fatal(err)}
	check(1)
}
