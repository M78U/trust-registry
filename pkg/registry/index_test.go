package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIndexSearchAndPagination(t *testing.T) {
	s:=newTestStore(t)
	at:=time.Now().UTC()
	a:=syntheticCA(t)
	b:=syntheticCA(t)
	x,err:=s.Import(a,"https://example.org/one",at);if err!=nil{t.Fatal(err)}
	y,err:=s.Import(b,"https://other.example/two",at);if err!=nil{t.Fatal(err)}
	if x.Certificate.FingerprintSHA256==y.Certificate.FingerprintSHA256 {t.Fatal("expected independent certificates")}
	if _,err:=s.Import(a,"https://EXAMPLE.org/again",at.Add(time.Second));err!=nil{t.Fatal(err)}
	i,err:=s.BuildIndex();if err!=nil{t.Fatal(err)}
	report,err:=i.Report();if err!=nil||report.Certificates!=2||report.ProvenanceRecords!=3{t.Fatalf("report: %+v %v",report,err)}
	for _,q:=range []Query{
		{Fingerprint:x.Certificate.FingerprintSHA256},
		{SourceHost:"EXAMPLE.ORG",PublicKeyAlgorithm:x.Certificate.PublicKeyAlgorithm},
		{SourceHost:"example.org",Subject:x.Certificate.Subject,Issuer:x.Certificate.Issuer,Serial:x.Certificate.SerialNumber,SKI:x.Certificate.SubjectKeyIdentifier,AKI:x.Certificate.AuthorityKeyIdentifier,SignatureAlgorithm:x.Certificate.SignatureAlgorithm},
	}{
		page,err:=i.Search(q);if err!=nil||len(page.Certificates)!=1||page.Certificates[0]!=x.Certificate||page.NextAfter!=""||page.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("query: %+v %v",page,err)}
	}
	none,err:=i.Search(Query{SourceHost:"example.org",Fingerprint:y.Certificate.FingerprintSHA256});if err!=nil||len(none.Certificates)!=0{t.Fatalf("AND: %+v %v",none,err)}
	page,err:=i.Search(Query{Limit:1});if err!=nil||len(page.Certificates)!=1||page.NextAfter==""{t.Fatalf("first page: %+v %v",page,err)}
	next,err:=i.Search(Query{Limit:1,After:page.NextAfter});if err!=nil||len(next.Certificates)!=1||next.NextAfter!=""||next.Certificates[0].FingerprintSHA256<=page.NextAfter{t.Fatalf("second page: %+v %v",next,err)}
	p,err:=i.Provenance(x.Certificate.FingerprintSHA256);if err!=nil||len(p)!=2{t.Fatalf("sources: %+v %v",p,err)}
	p[0].Record.SourceURL="changed"
	again,err:=i.ProvenanceByID(p[0].ID);if err!=nil||again.Record.SourceURL=="changed"{t.Fatal("index mutated")}
	for _,q:=range []Query{{Limit:-1},{Limit:1001},{SKI:"a"},{Serial:"01"},{After:"../x"},{Fingerprint:strings.Repeat("A",64)},{SourceHost:"https://example.org"}}{if _,err:=i.Search(q);err==nil{t.Fatalf("invalid query accepted: %+v",q)}}
	// A previously constructed index remains a snapshot. Rebuild rejects corruption.
	if err:=os.WriteFile(filepath.Join(s.root,"certificates",x.Certificate.FingerprintSHA256+".json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	if _,err:=s.BuildIndex();err==nil{t.Fatal("corrupt inventory indexed")}
}
