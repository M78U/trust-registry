package snapshot

import (
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
)
func TestPublicationTransition(t *testing.T){
 s,docs,o:=fixture(t)
 old,r,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
 if v,err:=CheckPublicationTransition(nil,old,"",true);err!=nil||v.HistoryStatus!="EXPLICIT_BOOTSTRAP_NO_PREVIOUS_BASELINE"{t.Fatal(v,err)}
 o.Sequence++;o.CreatedAt=o.CreatedAt.Add(time.Hour)
 next,_,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
 if v,err:=CheckPublicationTransition(old,next,r.SnapshotSHA256,false);err!=nil||v.NextSequence!=2||v.HistoryStatus!="APPEND_ONLY_PINNED_BASELINE_MATCHED"{t.Fatal(v,err)}
 if _,err:=CheckPublicationTransition(old,old,r.SnapshotSHA256,false);err==nil{t.Fatal("same sequence")}
 if _,err:=CheckPublicationTransition(old,next,"",false);err==nil{t.Fatal("missing pin")}
 if _,err:=CheckPublicationTransition(nil,next,"",true);err==nil{t.Fatal("invalid bootstrap")}
 omitted,_,err:=Build(s,docs[1:],o);if err!=nil{t.Fatal(err)}
 if _,err:=CheckPublicationTransition(old,omitted,r.SnapshotSHA256,false);err==nil{t.Fatal("omitted policy")}
 changed:=append([]policy.Document{},docs...)
 changed[0].Policy.Version++
 modified,_,err:=Build(s,changed,o);if err!=nil{t.Fatal(err)}
 if _,err:=CheckPublicationTransition(old,modified,r.SnapshotSHA256,false);err==nil{t.Fatal("replaced prior version")}
 o.Sequence++
 skipped,_,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
 if _,err:=CheckPublicationTransition(old,skipped,r.SnapshotSHA256,false);err==nil{t.Fatal("skipped sequence")}
}
