package snapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestResearchAuthentication(t *testing.T){
	s,docs,o:=fixture(t)
	raw,_,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
	pub1,key1,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	pub2,key2,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	a,err:=SignResearch(raw,key1);if err!=nil{t.Fatal(err)}
	b,err:=SignResearch(raw,key2);if err!=nil{t.Fatal(err)}
	encoded,err:=SignatureBytes(a);if err!=nil{t.Fatal(err)}
	a,err=DecodeSignature(encoded);if err!=nil{t.Fatal(err)}
	if _,err:=DecodeSignature(append([]byte(" "),encoded...));err==nil{t.Fatal("noncanonical accepted")}
	keys:=[]ed25519.PublicKey{pub1,pub2};sigs:=[]Signature{a,b}
	at:=o.CreatedAt.Add(time.Hour)
	r,err:=AuthenticateResearch(raw,sigs,keys,2,at,nil)
	if err!=nil||r.ReleaseAuthenticated||r.Report.ReleaseAuthenticated||r.TrustStatus!="NOT_ESTABLISHED"||r.ResearchSignatureStatus!="VERIFIED_PINNED_KEYS"||r.CheckpointStatus!="EXPLICIT_BOOTSTRAP_NO_ROLLBACK_CHECK"{t.Fatalf("authentication: %+v %v",r,err)}
	prev:=r.NextCheckpoint
	if _,err:=AuthenticateResearch(raw,sigs,keys,2,at,&prev);err!=nil{t.Fatal(err)}
	if _,err:=AuthenticateResearch(raw,sigs[:1],keys,2,at,nil);err==nil{t.Fatal("threshold bypass")}
	if _,err:=AuthenticateResearch(raw,[]Signature{a,a},keys,2,at,nil);err==nil{t.Fatal("duplicate signer")}
	if _,err:=AuthenticateResearch(raw,sigs,[]ed25519.PublicKey{pub1,pub1},2,at,nil);err==nil{t.Fatal("duplicate key")}
	if _,err:=AuthenticateResearch(raw,sigs,keys[:1],1,at,nil);err==nil{t.Fatal("unknown signer")}
	if _,err:=AuthenticateResearch(raw,sigs,keys,2,o.ExpiresAt,nil);err==nil{t.Fatal("expired snapshot")}
	if _,err:=AuthenticateResearch(raw,sigs,keys,2,o.CreatedAt.Add(-time.Second),nil);err==nil{t.Fatal("future snapshot")}
	if _,err:=AuthenticateResearch(raw,sigs,keys,2,at,&Checkpoint{prev.Sequence+1,prev.SnapshotSHA256});err==nil{t.Fatal("rollback")}
	if _,err:=AuthenticateResearch(raw,sigs,keys,2,at,&Checkpoint{prev.Sequence,strings.Repeat("f",64)});err==nil{t.Fatal("same sequence conflict")}
	changed:=append([]byte{},raw...);changed[0]^=1
	if _,err:=AuthenticateResearch(changed,sigs,keys,2,at,nil);err==nil{t.Fatal("tamper")}
	bad:=a;bad.Signature=append([]byte{},a.Signature...);bad.Signature[0]^=1
	if _,err:=AuthenticateResearch(raw,[]Signature{bad,b},keys,2,at,nil);err==nil{t.Fatal("bad signature")}
	o.Sequence++
	next,_,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
	n,err:=SignResearch(next,key1);if err!=nil{t.Fatal(err)}
	if _,err:=AuthenticateResearch(next,[]Signature{n},keys,1,at,&prev);err!=nil{t.Fatal(err)}
}
