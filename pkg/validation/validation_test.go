package validation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
)

func TestValidatePolicySet(t *testing.T){
	root:=t.TempDir()
	for _,d:=range []string{"certificates","provenance"}{if err:=os.Mkdir(filepath.Join(root,d),0700);err!=nil{t.Fatal(err)}}
	s,err:=registry.OpenStore(root);if err!=nil{t.Fatal(err)}
	d:=policy.Document{Policy:policy.Defaults()[0],Reviews:[]policy.Review{},Decisions:[]policy.Decision{}}
	next:=d;next.Policy.Version=2
	report,err:=Validate(s,[]policy.Document{d,next})
	if err!=nil||report.PolicyDocuments!=2||report.Certificates!=0||report.TrustStatus!=policy.Unknown||report.ReleaseAuthenticated{t.Fatalf("validation: %+v %v",report,err)}
	if _,err:=Validate(s,[]policy.Document{d,d});err==nil{t.Fatal("duplicate policy version accepted")}
	next.Policy.Purpose="timestamping"
	if _,err:=Validate(s,[]policy.Document{d,next});err==nil{t.Fatal("scope change accepted")}
	d.Policy.TrustAnchors=[]string{strings.Repeat("a",64)}
	if _,err:=Validate(s,[]policy.Document{d});err==nil{t.Fatal("dangling anchor accepted")}
	if _,err:=Validate(nil,nil);err==nil{t.Fatal("nil inventory accepted")}
}
