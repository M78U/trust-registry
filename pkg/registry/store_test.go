package registry

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s,err:=OpenStore(t.TempDir())
	if err!=nil { t.Fatal(err) }
	return s
}

func TestStoreRoundTripAndDedup(t *testing.T) {
	s:=newTestStore(t)
	der:=syntheticCA(t)
	pemBytes:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	a,err:=s.Import(der,"https://example.org/a",at)
	if err!=nil { t.Fatal(err) }
	repeat,err:=s.Import(der,"https://example.org/a",at)
	if err!=nil || repeat.ProvenanceID!=a.ProvenanceID { t.Fatalf("idempotency: %v",err) }
	b,err:=s.Import(pemBytes,"https://example.org/b",at.Add(time.Second))
	if err!=nil { t.Fatal(err) }
	if a.Certificate!=b.Certificate || a.ProvenanceID==b.ProvenanceID || a.Provenance.SourceFileSHA256==b.Provenance.SourceFileSHA256 { t.Fatal("certificate dedup or provenance independence failed") }
	rec,err:=s.Find(a.Certificate.FingerprintSHA256)
	if err!=nil || rec!=a.Certificate { t.Fatalf("find: %v",err) }
	sources,err:=s.Provenance(rec.FingerprintSHA256)
	if err!=nil || len(sources)!=2 { t.Fatalf("provenance: %v",err) }
	report,err:=s.Validate()
	if err!=nil || report.Certificates!=1 || report.ProvenanceRecords!=2 { t.Fatalf("validate: %+v %v",report,err) }
	raw,err:=os.ReadFile(filepath.Join(s.root,"certificates",rec.FingerprintSHA256+".der"))
	if err!=nil || !bytes.Equal(raw,der) { t.Fatalf("DER preservation: %v",err) }
}

func TestStoreRejectTampering(t *testing.T) {
	for _,kind:=range []string{"der","metadata","provenance","missing","orphan","unexpected"} {
		t.Run(kind,func(t *testing.T){
			s:=newTestStore(t)
			a,err:=s.Import(syntheticCA(t),"https://example.org/a",time.Now().UTC())
			if err!=nil { t.Fatal(err) }
			fp:=a.Certificate.FingerprintSHA256
			switch kind {
			case "der": err=os.WriteFile(filepath.Join(s.root,"certificates",fp+".der"),[]byte("corrupt"),0600)
			case "metadata": err=os.WriteFile(filepath.Join(s.root,"certificates",fp+".json"),[]byte("{}"),0600)
			case "provenance": err=os.WriteFile(filepath.Join(s.root,"provenance",a.ProvenanceID+".json"),[]byte("{}"),0600)
			case "missing": err=os.Remove(filepath.Join(s.root,"provenance",a.ProvenanceID+".json"))
			case "orphan":
				if err=os.Remove(filepath.Join(s.root,"certificates",fp+".der")); err==nil { err=os.Remove(filepath.Join(s.root,"certificates",fp+".json")) }
			case "unexpected": err=os.WriteFile(filepath.Join(s.root,"certificates","unknown.txt"),[]byte("unexpected"),0600)
			}
			if err!=nil { t.Fatal(err) }
			if _,err:=s.Validate(); err==nil { t.Fatal("invalid inventory accepted") }
		})
	}
}

func TestStoreRejectTraversalAndImmutableConflict(t *testing.T) {
	s:=newTestStore(t)
	der:=syntheticCA(t)
	at:=time.Now().UTC()
	a,err:=s.Import(der,"https://example.org/a",at)
	if err!=nil { t.Fatal(err) }
	for _,fp:=range []string{"../escape",strings.ToUpper(a.Certificate.FingerprintSHA256),strings.Repeat("z",64)} {
		if _,err:=s.Find(fp); err==nil { t.Fatal("invalid identifier accepted") }
	}
	path:=filepath.Join(s.root,"certificates",a.Certificate.FingerprintSHA256+".json")
	if err:=os.WriteFile(path,[]byte("tampered"),0600); err!=nil { t.Fatal(err) }
	if _,err:=s.Import(der,"https://example.org/a",at); err==nil { t.Fatal("immutable conflict accepted") }
	b,err:=os.ReadFile(path)
	if err!=nil || string(b)!="tampered" { t.Fatal("conflicting file overwritten") }
}
