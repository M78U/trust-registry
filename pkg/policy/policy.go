// Package policy evaluates explicit local policy declarations. It does not
// authenticate reviewers, validate certificate paths or establish release trust.
package policy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
)

const MaxRecords = 4096

const (
	Trusted = "TRUSTED"
	Suspended = "SUSPENDED"
	Distrusted = "DISTRUSTED"
	Unknown = "NOT_ESTABLISHED"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Constraints struct {
	RequireExplicitTrustDecision bool `json:"requireExplicitTrustDecision"`
	RequireValidCertificatePath bool `json:"requireValidCertificatePath"`
	AllowSystemTrustFallback bool `json:"allowSystemTrustFallback"`
}

type TrustPolicy struct {
	SchemaVersion string `json:"schemaVersion"`
	ID string `json:"id"`
	Version int `json:"version"`
	Jurisdiction string `json:"jurisdiction"`
	Purpose string `json:"purpose"`
	TrustAnchors []string `json:"trustAnchors"`
	IntermediateCandidates []string `json:"intermediateCandidates"`
	Constraints Constraints `json:"constraints"`
}

// Review is an independent local assertion about a particular provenance
// observation. A structurally valid review is not authenticated evidence.
type Review struct {
	ID string `json:"id"`
	ProvenanceID string `json:"provenanceId"`
	CertificateSHA256 string `json:"certificateSHA256"`
	Status string `json:"status"`
	RecordedAt time.Time `json:"recordedAt"`
	Evidence []string `json:"evidence"`
	ReviewReferences []string `json:"reviewReferences"`
}

type Decision struct {
	ID string `json:"id"`
	CertificateSHA256 string `json:"certificateSHA256"`
	PolicyID string `json:"policyId"`
	PolicyVersion int `json:"policyVersion"`
	Role string `json:"role"`
	Status string `json:"status"`
	RecordedAt time.Time `json:"recordedAt"`
	EffectiveFrom time.Time `json:"effectiveFrom"`
	EffectiveUntil *time.Time `json:"effectiveUntil"`
	Reason string `json:"reason"`
	EvidenceIDs []string `json:"evidenceIds"`
	ReviewReferences []string `json:"reviewReferences"`
}

// Document is a local review input, not an authenticated snapshot. Git/PR
// governance owns append-only history across revisions.
type Document struct {
	Policy TrustPolicy `json:"policy"`
	Reviews []Review `json:"reviews"`
	Decisions []Decision `json:"decisions"`
}

type AnchorEvaluation struct {
	FingerprintSHA256 string `json:"fingerprintSHA256"`
	Status string `json:"status"`
	DecisionID string `json:"decisionId,omitempty"`
	Reason string `json:"reason"`
}

type Evaluation struct {
	PolicyID string `json:"policyId"`
	PolicyVersion int `json:"policyVersion"`
	Purpose string `json:"purpose"`
	EvaluationTime time.Time `json:"evaluationTime"`
	KnowledgeTime time.Time `json:"knowledgeTime"`
	Mode string `json:"mode"`
	TrustStatus string `json:"trustStatus"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
	LocallyAuthorizedAnchors []string `json:"locallyAuthorizedAnchors"`
	IntermediateCandidates []string `json:"intermediateCandidates"`
	AnchorEvaluations []AnchorEvaluation `json:"anchorEvaluations"`
	Constraints Constraints `json:"constraints"`
}

func knownPurpose(s string) bool {
	switch s {
	case "document-signing","electronic-seal-signing","seal-maker","timestamping","code-signing","device-authentication","client-authentication","server-authentication":
		return true
	}
	return false
}

func validTime(t time.Time) bool { return !t.IsZero() && t.Location()==time.UTC && t.Year()>=1 && t.Year()<=9999 }
func validStrings(s []string) bool {
	if len(s)==0 || len(s)>MaxRecords { return false }
	seen:=map[string]bool{}
	for _,v:=range s { if strings.TrimSpace(v)=="" || len(v)>4096 || seen[v] { return false }; seen[v]=true }
	return true
}
func validFingerprints(s []string) bool {
	if s==nil || len(s)>MaxRecords { return false }
	seen:=map[string]bool{}
	for _,v:=range s { if !fingerprintPattern.MatchString(v) || seen[v] { return false }; seen[v]=true }
	return true
}

func (p TrustPolicy) Validate() error {
	if p.SchemaVersion!="1" || !idPattern.MatchString(p.ID) || p.Version<1 || !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(p.Jurisdiction) || !knownPurpose(p.Purpose) { return errors.New("invalid policy identity, jurisdiction or purpose") }
	if !p.Constraints.RequireExplicitTrustDecision || !p.Constraints.RequireValidCertificatePath || p.Constraints.AllowSystemTrustFallback { return errors.New("unsafe policy constraints") }
	if !validFingerprints(p.TrustAnchors) || !validFingerprints(p.IntermediateCandidates) { return errors.New("invalid or duplicate policy fingerprints") }
	anchors:=map[string]bool{}
	for _,fp:=range p.TrustAnchors { anchors[fp]=true }
	for _,fp:=range p.IntermediateCandidates { if anchors[fp] { return errors.New("certificate cannot occupy both roles in one policy") } }
	return nil
}

// Defaults returns new empty policies; none are pre-authorized.
func Defaults() []TrustPolicy {
	result:=make([]TrustPolicy,0,4)
	for _,purpose:=range []string{"document-signing","electronic-seal-signing","seal-maker","timestamping"} {
		result=append(result,TrustPolicy{"1","cn."+purpose,1,"CN",purpose,[]string{},[]string{},Constraints{true,true,false}})
	}
	return result
}

// inventory returns checked references. An empty policy with no records
// requires no inventory. Referenced certificates must be in a validated store.
func (d Document) validate(s *registry.Store) (map[string]Review,error) {
	if err:=d.Policy.Validate();err!=nil { return nil,err }
	var index *registry.Index
	if len(d.Policy.TrustAnchors)>0 || len(d.Policy.IntermediateCandidates)>0 || len(d.Reviews)>0 || len(d.Decisions)>0 {
		var err error
		index,err=s.BuildIndex()
		if err!=nil { return nil,fmt.Errorf("inventory: %w",err) }
	}
	return d.validateIndex(index)
}

// ValidateAgainst checks document semantics and references against a shared
// validated inventory. It makes no trust or authenticity determination.
func (d Document) ValidateAgainst(index *registry.Index) error {
	_,err:=d.validateIndex(index)
	return err
}

func (d Document) validateIndex(index *registry.Index) (map[string]Review,error) {
	p:=d.Policy
	if err:=p.Validate(); err!=nil { return nil,err }
	if d.Reviews==nil || d.Decisions==nil || len(d.Reviews)>MaxRecords || len(d.Decisions)>MaxRecords { return nil,errors.New("invalid review or decision collection") }
	anchors:=map[string]bool{}
	refs:=map[string]bool{}
	for _,fp:=range p.TrustAnchors { anchors[fp]=true; refs[fp]=true }
	for _,fp:=range p.IntermediateCandidates { refs[fp]=true }
	if len(refs)>0 || len(d.Reviews)>0 || len(d.Decisions)>0 {
		if _,err:=index.Report();err!=nil { return nil,fmt.Errorf("inventory: %w",err) }
	}
	for fp:=range refs { if _,err:=index.Find(fp);err!=nil { return nil,fmt.Errorf("policy certificate %s: %w",fp,err) } }
	reviews:=map[string]Review{}
	reviewTimes:=map[string]map[time.Time]bool{}
	for _,r:=range d.Reviews {
		if !idPattern.MatchString(r.ID) || reviews[r.ID].ID!="" || !fingerprintPattern.MatchString(r.ProvenanceID) || !fingerprintPattern.MatchString(r.CertificateSHA256) ||
			(r.Status!="PROVENANCE_VERIFIED" && r.Status!="REVIEW_REJECTED") || !validTime(r.RecordedAt) || !validStrings(r.Evidence) || !validStrings(r.ReviewReferences) { return nil,errors.New("invalid or duplicate provenance review") }
		entry,err:=index.ProvenanceByID(r.ProvenanceID)
		if err!=nil || entry.Record.CertificateSHA256!=r.CertificateSHA256 || r.RecordedAt.Before(entry.Record.RecordedAt) { return nil,errors.New("review references missing, mismatched or future provenance observation") }
		if reviewTimes[r.ProvenanceID]==nil { reviewTimes[r.ProvenanceID]=map[time.Time]bool{} }
		if reviewTimes[r.ProvenanceID][r.RecordedAt] { return nil,errors.New("ambiguous provenance review history") }
		reviewTimes[r.ProvenanceID][r.RecordedAt]=true
		reviews[r.ID]=r
	}
	decisionIDs:=map[string]bool{}
	effectiveTimes:=map[string]map[time.Time]bool{}
	for _,v:=range d.Decisions {
		if !idPattern.MatchString(v.ID) || decisionIDs[v.ID] || !anchors[v.CertificateSHA256] || v.PolicyID!=p.ID || v.PolicyVersion!=p.Version || v.Role!="TRUST_ANCHOR" ||
			(v.Status!=Trusted && v.Status!=Suspended && v.Status!=Distrusted) || !validTime(v.RecordedAt) || !validTime(v.EffectiveFrom) ||
			(v.EffectiveUntil!=nil && (!validTime(*v.EffectiveUntil) || !v.EffectiveUntil.After(v.EffectiveFrom))) ||
			strings.TrimSpace(v.Reason)=="" || len(v.Reason)>4096 || !validStrings(v.ReviewReferences) || v.EvidenceIDs==nil || len(v.EvidenceIDs)>MaxRecords { return nil,errors.New("invalid, duplicate or out-of-scope decision") }
		decisionIDs[v.ID]=true
		if effectiveTimes[v.CertificateSHA256]==nil { effectiveTimes[v.CertificateSHA256]=map[time.Time]bool{} }
		if effectiveTimes[v.CertificateSHA256][v.EffectiveFrom] { return nil,errors.New("ambiguous decision effective time") }
		effectiveTimes[v.CertificateSHA256][v.EffectiveFrom]=true
		if v.Status==Trusted && (!validStrings(v.EvidenceIDs) || v.EffectiveFrom.Before(v.RecordedAt)) { return nil,errors.New("positive decision needs evidence and cannot predate its recording") }
		seen:=map[string]bool{}
		for _,id:=range v.EvidenceIDs {
			review,ok:=reviews[id]
			if !ok || seen[id] || review.CertificateSHA256!=v.CertificateSHA256 || review.RecordedAt.After(v.RecordedAt) || (v.Status==Trusted && review.Status!="PROVENANCE_VERIFIED") { return nil,errors.New("invalid decision evidence reference") }
			seen[id]=true
		}
	}
	return reviews,nil
}

// Evaluate uses explicit effective and knowledge time. Newer effective events
// supersede older ones permanently, even when the newer event expires.
// Rejected or superseded evidence cannot support a positive authorization.
// A local authorization is never a production trust result.
func (d Document) Evaluate(s *registry.Store, at, knownAt time.Time) (Evaluation,error) {
	if !validTime(at) || !validTime(knownAt) || knownAt.Before(at) { return Evaluation{},errors.New("UTC evaluation and knowledge times required; knowledge time must not precede evaluation") }
	reviews,err:=d.validate(s)
	if err!=nil { return Evaluation{},err }
	p:=d.Policy
	report:=Evaluation{PolicyID:p.ID,PolicyVersion:p.Version,Purpose:p.Purpose,EvaluationTime:at,KnowledgeTime:knownAt,Mode:"UNAUTHENTICATED_LOCAL_POLICY",TrustStatus:Unknown,ReleaseAuthenticated:false,LocallyAuthorizedAnchors:[]string{},IntermediateCandidates:append([]string{},p.IntermediateCandidates...),AnchorEvaluations:[]AnchorEvaluation{},Constraints:p.Constraints}
	latestReviews:=map[string]Review{}
	for _,r:=range reviews {
		if r.RecordedAt.After(knownAt) { continue }
		current,ok:=latestReviews[r.ProvenanceID]
		if !ok || r.RecordedAt.After(current.RecordedAt) { latestReviews[r.ProvenanceID]=r }
	}
	latest:=map[string]Decision{}
	for _,v:=range d.Decisions {
		if v.RecordedAt.After(knownAt) || v.EffectiveFrom.After(at) { continue }
		old,ok:=latest[v.CertificateSHA256]
		if !ok || v.EffectiveFrom.After(old.EffectiveFrom) { latest[v.CertificateSHA256]=v }
	}
	fps:=append([]string{},p.TrustAnchors...)
	sort.Strings(fps)
	sort.Strings(report.IntermediateCandidates)
	for _,fp:=range fps {
		row:=AnchorEvaluation{FingerprintSHA256:fp,Status:Unknown,Reason:"no applicable decision"}
		if v,ok:=latest[fp]; ok {
			row.DecisionID=v.ID
			switch {
			case v.EffectiveUntil!=nil && !at.Before(*v.EffectiveUntil):
				row.Reason="latest decision expired; older decisions do not resume"
			case v.Status!=Trusted:
				row.Status=v.Status;row.Reason=v.Reason
			default:
				valid:=true
				for _,id:=range v.EvidenceIDs { r:=reviews[id]; current:=latestReviews[r.ProvenanceID]; if current.ID!=id || current.Status!="PROVENANCE_VERIFIED" { valid=false;break } }
				if !valid { row.Reason="positive decision evidence rejected or superseded" } else {
					row.Status=Trusted;row.Reason=v.Reason
					report.LocallyAuthorizedAnchors=append(report.LocallyAuthorizedAnchors,fp)
				}
			}
		}
		report.AnchorEvaluations=append(report.AnchorEvaluations,row)
	}
	return report,nil
}
