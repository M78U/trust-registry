package validation

import (
	"errors"
	"time"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
)

type LocalPathReport struct {
	Policy policy.Evaluation `json:"policy"`
	Path registry.PathValidationReport `json:"path"`
	BusinessPurposeStatus string `json:"businessPurposeStatus"`
	TrustStatus string `json:"trustStatus"`
}

// VerifyLocalPath binds path validation to an exact local policy purpose and
// the currently authorized anchors. It cannot authenticate policy history,
// review evidence, business purpose, revocation or release trust.
func VerifyLocalPath(s *registry.Store,d policy.Document,input []byte,purpose,dnsName string,at,knownAt time.Time)(LocalPathReport,error){
	if purpose==""||purpose!=d.Policy.Purpose{return LocalPathReport{},errors.New("requested purpose must match policy")}
	var profile string
	switch purpose{
	case "document-signing","electronic-seal-signing","seal-maker","device-authentication":profile="signature"
	case "timestamping","code-signing","client-authentication","server-authentication":profile=purpose
	default:return LocalPathReport{},errors.New("unsupported policy purpose")
	}
	e,err:=d.Evaluate(s,at,knownAt);if err!=nil{return LocalPathReport{},err}
	// Suspended/distrusted anchors must never be reused as intermediates.
	path,err:=s.VerifyPath(input,registry.PathOptions{AnchorFingerprints:e.LocallyAuthorizedAnchors,IntermediateFingerprints:e.IntermediateCandidates,At:at,Profile:profile,DNSName:dnsName})
	if err!=nil{return LocalPathReport{},err}
	return LocalPathReport{e,path,"NOT_ESTABLISHED",policy.Unknown},nil
}
