package tufclient

import (
	"errors"
	"time"
)

// RefreshObservation is caller-owned evidence of a successful explicit strict
// online refresh followed by reopening the exact installed release. The SDK
// does not authenticate this record or persist it. Never construct it from an
// offline open, a failed refresh, or the installed evidence acceptance time.
type RefreshObservation struct {
	InitialRootSHA256 string `json:"initialRootSHA256"`
	AuthoritySHA256 string `json:"authoritySHA256"`
	Checkpoint ReleaseCheckpoint `json:"checkpoint"`
	CompletedAt time.Time `json:"completedAt"`
}

type RefreshPlanOptions struct {
	DiagnosticOptions
	LastOnline *RefreshObservation
	MaxOnlineAge time.Duration
	ExpiryLead time.Duration
}

// RefreshPlan is advisory only. It does not authorize an update or guarantee
// that the remote repository is unchanged. Diagnostic retains precedence.
type RefreshPlan struct {
	Diagnostic StateDiagnostic `json:"diagnostic"`
	Status string `json:"status"`
	RefreshSuggested bool `json:"refreshSuggested"`
	NextCheckAt *time.Time `json:"nextCheckAt,omitempty"`
	ObservationMatched bool `json:"observationMatched"`
	TrustStatus string `json:"trustStatus"`
}

// PlanRefresh runs one bounded local diagnosis. No network, automatic recovery,
// persistent writes (other than the existing cooperative diagnostic lock),
// timers, or consumer sessions are introduced.
func PlanRefresh(o RefreshPlanOptions) (RefreshPlan, error) {
	if o.LastOnline != nil {
		copy := *o.LastOnline
		o.LastOnline = &copy
	}
	if err := validateRefreshPlanOptions(o, time.Now().UTC()); err != nil {
		return RefreshPlan{}, err
	}
	d, err := DiagnoseState(o.DiagnosticOptions)
	if err != nil {
		return RefreshPlan{}, err
	}
	return planRefreshFromDiagnostic(o, d, o.Authority.SHA256())
}

func validateRefreshPlanOptions(o RefreshPlanOptions, now time.Time) error {
	if !validTime(now) || o.MaxOnlineAge < time.Minute || o.MaxOnlineAge > 30*24*time.Hour ||
		o.ExpiryLead < 0 || o.ExpiryLead > 24*time.Hour {
		return errors.New("refresh plan requires explicit age of 1 minute to 30 days and expiry lead of 0 to 24 hours")
	}
	if x := o.LastOnline; x != nil {
		if !hashPattern.MatchString(x.InitialRootSHA256) || !hashPattern.MatchString(x.AuthoritySHA256) ||
			!validTime(x.CompletedAt) || x.CompletedAt.After(now) || x.Checkpoint.validate() != nil {
			return errors.New("invalid caller-owned online refresh observation")
		}
	}
	return nil
}

func planRefreshFromDiagnostic(o RefreshPlanOptions, d StateDiagnostic, authoritySHA256 string) (RefreshPlan, error) {
	if err := validateRefreshPlanOptions(o, d.CheckedAt); err != nil {
		return RefreshPlan{}, err
	}
	p := RefreshPlan{Diagnostic: d, Status: "DIAGNOSTIC_ACTION_REQUIRED", TrustStatus: "NOT_ESTABLISHED"}
	// Never let an advisory age or expiry policy hide recovery, expiry, a
	// missing state, a checkpoint conflict or a busy lock.
	if d.Status != "INSTALLED_EVIDENCE_MATCHES" {
		return p, nil
	}
	v := d.Installed
	if v == nil || !v.CacheMatches || !v.CheckpointMatches || v.Expired ||
		!validTime(v.ValidUntil) || !d.CheckedAt.Before(v.ValidUntil) ||
		v.Sequence == 0 || v.RootVersion < 1 || !hashPattern.MatchString(v.SnapshotSHA256) ||
		!hashPattern.MatchString(o.InitialRootSHA256) ||
		!hashPattern.MatchString(authoritySHA256) {
		return RefreshPlan{}, errors.New("inconsistent healthy refresh diagnostic")
	}
	// Offline verification or a previously accepted target is not an online
	// freshness observation. Missing/mismatched caller records are due now.
	if x := o.LastOnline; x == nil || x.InitialRootSHA256 != o.InitialRootSHA256 ||
		x.AuthoritySHA256 != authoritySHA256 ||
		x.Checkpoint != (ReleaseCheckpoint{Sequence: v.Sequence, SnapshotSHA256: v.SnapshotSHA256, RootVersion: v.RootVersion}) {
		p.Status = "ONLINE_OBSERVATION_REQUIRED"
		p.RefreshSuggested = true
		return p, nil
	}
	p.ObservationMatched = true
	ageDue := o.LastOnline.CompletedAt.Add(o.MaxOnlineAge)
	expiryDue := v.ValidUntil.Add(-o.ExpiryLead)
	due := ageDue
	p.Status = "ONLINE_AGE_DUE"
	if !expiryDue.After(ageDue) {
		due = expiryDue
		p.Status = "SIGNED_EXPIRY_APPROACHING"
	}
	if !validTime(due) {
		return RefreshPlan{}, errors.New("refresh planning time outside supported range")
	}
	p.NextCheckAt = &due
	p.RefreshSuggested = !d.CheckedAt.Before(due)
	if !p.RefreshSuggested {
		p.Status = "NOT_DUE_UNDER_LOCAL_POLICY"
	}
	return p, nil
}
