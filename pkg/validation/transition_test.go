package validation

import (
 "testing"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
)
func TestTransitionPreservesPriorVersions(t *testing.T){
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 d:=policy.Document{Policy:policy.Defaults()[0],Reviews:[]policy.Review{},Decisions:[]policy.Decision{}}
 next:=d;next.Policy.Version=2
 r,err:=ValidateTransition(s,[]policy.Document{d},[]policy.Document{next,d})
 if err!=nil||len(r.Revisions)!=1||len(r.AddedPolicyVersions)!=1||r.ReleaseAuthenticated{t.Fatalf("%+v %v",r,err)}
 if _,err:=ValidateTransition(s,[]policy.Document{d},[]policy.Document{next});err==nil{t.Fatal("old version omission")}
 if _,err:=ValidateTransition(s,[]policy.Document{next},[]policy.Document{d,next});err==nil{t.Fatal("historical insertion")}
}
