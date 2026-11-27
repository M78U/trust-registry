package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func graphKey(t *testing.T)*ecdsa.PrivateKey{
	t.Helper()
	k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	return k
}

func graphCert(t *testing.T,serial int64,name string,ca bool,key,signer *ecdsa.PrivateKey,parent *x509.Certificate)([]byte,*x509.Certificate){
	t.Helper()
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	c:=&x509.Certificate{SerialNumber:big.NewInt(serial),Subject:pkix.Name{CommonName:name},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:ca,KeyUsage:x509.KeyUsageDigitalSignature}
	if ca{c.KeyUsage|=x509.KeyUsageCertSign}
	if parent==nil{parent=c}
	raw,err:=x509.CreateCertificate(rand.Reader,c,parent,&key.PublicKey,signer);if err!=nil{t.Fatal(err)}
	parsed,err:=x509.ParseCertificate(raw);if err!=nil{t.Fatal(err)}
	return raw,parsed
}

func TestGraphCrossSigningAndEphemeralLeaf(t *testing.T){
	s:=newTestStore(t)
	at:=time.Now().UTC()
	ka,kb,ki,kw,kl:=graphKey(t),graphKey(t),graphKey(t),graphKey(t),graphKey(t)
	a,pa:=graphCert(t,1,"Root A",true,ka,ka,nil)
	b,pb:=graphCert(t,2,"Root B",true,kb,kb,nil)
	ia,pia:=graphCert(t,3,"Shared CA",true,ki,ka,pa)
	ib,_:=graphCert(t,4,"Shared CA",true,ki,kb,pb)
	wrong,_:=graphCert(t,5,"Shared CA",true,kw,ka,pa)
	leaf,_:=graphCert(t,6,"Synthetic leaf",false,kl,ki,pia)
	for _,raw:=range [][]byte{a,b,ia,ib,wrong}{if _,err:=s.Import(raw,"https://example.org/graph",at);err!=nil{t.Fatal(err)}}
	g,err:=s.BuildGraph(leaf);if err!=nil{t.Fatal(err)}
	view,err:=g.Export();if err!=nil||len(view.Nodes)!=6||view.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("graph: %+v %v",view,err)}
	var rejected,matched int
	for _,e:=range view.Edges{
		if e.ChildSHA256!=digest(leaf){continue}
		if e.DirectIssuerStatus=="MATCHED"{matched++}
		if e.IssuerSHA256==digest(wrong)&&e.SignatureStatus!="VERIFIED"&&e.DirectIssuerStatus!="MATCHED"{rejected++}
	}
	if matched!=2||rejected!=1{t.Fatalf("matched %d rejected %d",matched,rejected)}
	for _,n:=range view.Nodes{if n.Certificate.FingerprintSHA256==digest(leaf)&&n.InInventory{t.Fatal("leaf persisted")}}
	r,err:=g.Paths(digest(leaf),MaxPathDepth)
	if err!=nil||len(r.Paths)!=2||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("paths: %+v %v",r,err)}
	for _,path:=range r.Paths{if len(path.Fingerprints)!=3||path.TerminalStatus!="SELF_SIGNATURE_VERIFIED"{t.Fatalf("path: %+v",path)}}
	short,err:=g.Paths(digest(leaf),1)
	if err!=nil||len(short.Paths)!=1||short.Paths[0].TerminalStatus!="DEPTH_LIMIT"{t.Fatalf("depth: %+v %v",short,err)}
	view.Nodes[0].Certificate.Subject="modified"
	again,_:=g.Export()
	if again.Nodes[0].Certificate.Subject=="modified"{t.Fatal("graph mutated")}
	g2,err:=s.BuildGraph(leaf);if err!=nil{t.Fatal(err)}
	v2,_:=g2.Export()
	x,_:=json.Marshal(again);y,_:=json.Marshal(v2)
	if string(x)!=string(y){t.Fatal("graph not deterministic")}
	if err:=os.WriteFile(filepath.Join(s.root,"certificates",digest(a)+".json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	if _,err:=s.BuildGraph(nil);err==nil{t.Fatal("corrupt inventory accepted")}
}

func TestGraphCycleAndMissingIssuer(t *testing.T){
	s:=newTestStore(t)
	at:=time.Now().UTC()
	ka,kb:=graphKey(t),graphKey(t)
	_,pa:=graphCert(t,10,"Cycle A",true,ka,ka,nil)
	_,pb:=graphCert(t,11,"Cycle B",true,kb,kb,nil)
	a,_:=graphCert(t,12,"Cycle A",true,ka,kb,pb)
	b,_:=graphCert(t,13,"Cycle B",true,kb,ka,pa)
	if _,err:=s.Import(a,"https://example.org/graph",at);err!=nil{t.Fatal(err)}
	g,err:=s.BuildGraph(nil);if err!=nil{t.Fatal(err)}
	r,err:=g.Paths(digest(a),MaxPathDepth)
	if err!=nil||len(r.Paths)!=1||r.Paths[0].TerminalStatus!="NO_MATCHED_ISSUER"{t.Fatalf("missing: %+v %v",r,err)}
	if _,err:=s.Import(b,"https://example.org/graph",at);err!=nil{t.Fatal(err)}
	g,err=s.BuildGraph(nil);if err!=nil{t.Fatal(err)}
	r,err=g.Paths(digest(a),MaxPathDepth)
	if err!=nil||len(r.Paths)!=1||r.Paths[0].TerminalStatus!="CYCLE"||len(r.Paths[0].Fingerprints)!=3||r.Paths[0].Fingerprints[2]!=digest(a){t.Fatalf("cycle: %+v %v",r,err)}
	if _,err:=g.Paths(strings.Repeat("f",64),MaxPathDepth);err==nil{t.Fatal("unknown start accepted")}
	if _,err:=g.Paths(digest(a),MaxPathDepth+1);err==nil{t.Fatal("invalid depth accepted")}
}
