// Package validation checks local inventory and supplied policy documents.
// A successful validation is not authenticated distribution or certificate trust.
package validation

import (
	"errors"
	"fmt"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
)

const MaxPolicyDocuments = 256

type Report struct {
	registry.ValidationReport
	PolicyDocuments int `json:"policyDocuments"`
	ProvenanceReviews int `json:"provenanceReviews"`
	TrustDecisions int `json:"trustDecisions"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
	TrustStatus string `json:"trustStatus"`
}

// Validate checks the whole inventory once and every explicitly supplied policy.
// It rejects duplicate policy IDs/versions and changing scope under one ID.
// A caller must supply all intended documents; omission or historical deletion
// cannot be detected without an authenticated manifest.
func Validate(s *registry.Store, documents []policy.Document) (Report,error) {
	if len(documents)>MaxPolicyDocuments { return Report{},errors.New("policy document limit exceeded") }
	idx,err:=s.BuildIndex()
	if err!=nil { return Report{},err }
	inventory,err:=idx.Report()
	if err!=nil { return Report{},err }
	report:=Report{ValidationReport:inventory,TrustStatus:policy.Unknown}
	type scope struct { jurisdiction,purpose string }
	type versionKey struct { id string; version int }
	scopes:=make(map[string]scope)
	seen:=make(map[versionKey]bool)
	for n,d:=range documents {
		if err:=d.ValidateAgainst(idx);err!=nil { return Report{},fmt.Errorf("policy document %d: %w",n+1,err) }
		p:=d.Policy
		k:=versionKey{p.ID,p.Version}
		if seen[k] { return Report{},fmt.Errorf("duplicate policy version: %s/%d",p.ID,p.Version) }
		seen[k]=true
		current:=scope{p.Jurisdiction,p.Purpose}
		if old,ok:=scopes[p.ID];ok && old!=current { return Report{},fmt.Errorf("policy scope changed across versions: %s",p.ID) }
		scopes[p.ID]=current
		report.PolicyDocuments++
		report.ProvenanceReviews+=len(d.Reviews)
		report.TrustDecisions+=len(d.Decisions)
	}
	return report,nil
}
