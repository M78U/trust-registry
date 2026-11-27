package snapshot

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
)

func fixture(t *testing.T)(*registry.Store,[]policy.Document,Options){
	t.Helper()
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	c:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic snapshot CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,c,c,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
	if _,err:=s.Import(der,"https://example.org/synthetic",at);err!=nil{t.Fatal(err)}
	docs:=[]policy.Document{}
	for _,p:=range policy.Defaults(){docs=append(docs,policy.Document{Policy:p,Reviews:[]policy.Review{},Decisions:[]policy.Decision{}})}
	return s,docs,Options{1,strings.Repeat("a",40),at,at.AddDate(0,1,0)}
}
func TestDeterministicSnapshot(t *testing.T){
	s,docs,o:=fixture(t)
	a,r,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
	for i,j:=0,len(docs)-1;i<j;i,j=i+1,j-1{docs[i],docs[j]=docs[j],docs[i]}
	b,_,err:=Build(s,docs,o);if err!=nil||!bytes.Equal(a,b){t.Fatalf("not deterministic: %v",err)}
	v,err:=Verify(a,r.ManifestSHA256)
	if err!=nil||!v.ExpectedManifestMatched||v.Validation.Certificates!=1||v.Validation.ProvenanceRecords!=1||v.Validation.PolicyDocuments!=4||v.ReleaseAuthenticated||v.TrustStatus!="NOT_ESTABLISHED"||v.FreshnessStatus!="NOT_CHECKED"{t.Fatalf("verify: %+v %v",v,err)}
	if _,err:=Verify(a,strings.Repeat("b",64));err==nil{t.Fatal("wrong pin accepted")}
}
func TestTamperingAndCanonicalRules(t *testing.T){
	s,docs,o:=fixture(t)
	raw,_,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
	for _,kind:=range []string{"hash","extra","missing","traversal","duplicate","expiry","semantic"}{
		var e Envelope
		if err:=json.Unmarshal(raw,&e);err!=nil{t.Fatal(err)}
		switch kind{
		case "hash":e.Payload[0].Data[0]^=1
		case "extra":e.Payload=append(e.Payload,e.Payload[0])
		case "missing":e.Payload=e.Payload[1:]
		case "traversal":e.Manifest.Files[0].Path="../outside";e.Payload[0].Path="../outside"
		case "duplicate":e.Manifest.Files[1]=e.Manifest.Files[0];e.Payload[1]=e.Payload[0]
		case "expiry":e.Manifest.ExpiresAt=e.Manifest.CreatedAt
		case "semantic":
			for i,f:=range e.Payload{if strings.HasPrefix(f.Path,"certificates/")&&strings.HasSuffix(f.Path,".json"){e.Payload[i].Data=[]byte("{}");e.Manifest.Files[i].Size=2;e.Manifest.Files[i].SHA256=digest([]byte("{}"));break}}
		}
		b,_:=canonical(e)
		if _,err:=Verify(b,"");err==nil{t.Fatalf("tamper accepted: %s",kind)}
	}
	for _,b:=range [][]byte{append([]byte(" "),raw...),bytes.Replace(raw,[]byte(`"sequence":1`),[]byte(`"sequence":1,"sequence":1`),1),append(bytes.Clone(raw),[]byte("{}")...)}{if _,err:=Verify(b,"");err==nil{t.Fatal("noncanonical input accepted")}}
}
func TestEmptySnapshot(t *testing.T){
	s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
	if _,err:=s.Init();err!=nil{t.Fatal(err)}
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	_,r,err:=Build(s,nil,Options{1,strings.Repeat("a",40),at,at.Add(time.Hour)})
	if err!=nil||len(r.Manifest.Files)!=0||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("empty: %+v %v",r,err)}
}
