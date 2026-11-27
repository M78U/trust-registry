package tufclient

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type UpdateMode string

const (
	UpdatePlan UpdateMode = "plan"
	UpdateOpen UpdateMode = "open"
	UpdateRecoverPending UpdateMode = "recover-pending"
	UpdateRecoverRoot UpdateMode = "recover-root"
	UpdateRefresh UpdateMode = "refresh"
)

// CoordinateOptions contains one independently pinned state identity and one
// explicit action. The zero mode is plan-only. No mode creates a new state.
type CoordinateOptions struct {
	DiagnosticOptions
	Mode UpdateMode
	ExpectedRootHeadSHA256 string
	MetadataURL string
	TargetsURL string
	// Optional advisory policy, only valid for the explicit plan mode.
	RefreshPolicy *RefreshPlanningPolicy
}

// RefreshPlanningPolicy is local caller policy, not update authorization.
type RefreshPlanningPolicy struct {
	LastOnline *RefreshObservation
	MaxOnlineAge time.Duration
	ExpiryLead time.Duration
}

type UpdateResult struct {
	Mode UpdateMode `json:"mode"`
	Status string `json:"status"`
	Diagnostic *StateDiagnostic `json:"diagnostic,omitempty"`
	ActionAttempted bool `json:"actionAttempted"`
	ActionCompleted bool `json:"actionCompleted"`
	RootRecovery *RootRecoveryReport `json:"rootRecovery,omitempty"`
	Install *Report `json:"install,omitempty"`
	Consumer *ConsumerInfo `json:"consumer,omitempty"`
	Checkpoint *ReleaseCheckpoint `json:"checkpoint,omitempty"`
	RefreshPlan *RefreshPlan `json:"refreshPlan,omitempty"`
	OnlineObservation *RefreshObservation `json:"onlineObservation,omitempty"`
	TrustStatus string `json:"trustStatus"`
}

// CoordinateUpdate does not run a daemon, retry, bootstrap, fall back or
// implicitly authorize a different action. Each operation reacquires the
// existing lock and performs its own validation; this is not one transaction.
func CoordinateUpdate(ctx context.Context,o CoordinateOptions)(UpdateResult,*ConsumerSession,error){
	return coordinateUpdate(ctx,o,nil)
}

func coordinateUpdate(ctx context.Context,o CoordinateOptions,client *http.Client)(UpdateResult,*ConsumerSession,error){
	if o.Mode==""{o.Mode=UpdatePlan}
	result:=UpdateResult{Mode:o.Mode,Status:"INVALID_OPTIONS",TrustStatus:"NOT_ESTABLISHED"}
	fail:=func(status string,err error)(UpdateResult,*ConsumerSession,error){
		result.Status=status
		return result,nil,err
	}
	if ctx==nil{return fail("INVALID_OPTIONS",errors.New("context required"))}
	switch o.Mode{
	case UpdatePlan,UpdateOpen,UpdateRecoverPending,UpdateRecoverRoot,UpdateRefresh:
	default:return fail("INVALID_OPTIONS",errors.New("unknown update mode"))
	}
	if o.Mode==UpdateRecoverRoot{
		if !hashPattern.MatchString(o.ExpectedRootHeadSHA256){return fail("INVALID_OPTIONS",errors.New("explicit archived head digest required"))}
	}else if o.ExpectedRootHeadSHA256!=""{return fail("INVALID_OPTIONS",errors.New("archived head digest only valid for root recovery"))}
	if o.Mode==UpdateRefresh{
		if _,err:=baseURL(o.MetadataURL);err!=nil{return fail("INVALID_OPTIONS",err)}
		if _,err:=baseURL(o.TargetsURL);err!=nil{return fail("INVALID_OPTIONS",err)}
	}else if o.MetadataURL!=""||o.TargetsURL!=""{return fail("INVALID_OPTIONS",errors.New("repository URLs only valid for explicit refresh"))}
	// Copy caller-owned advisory inputs before the diagnosis.
	var planning *RefreshPlanOptions
	if p:=o.RefreshPolicy;p!=nil{
		if o.Mode!=UpdatePlan{return fail("INVALID_OPTIONS",errors.New("refresh policy only valid for plan mode"))}
		plan:=RefreshPlanOptions{DiagnosticOptions:o.DiagnosticOptions,MaxOnlineAge:p.MaxOnlineAge,ExpiryLead:p.ExpiryLead}
		if p.LastOnline!=nil{x:=*p.LastOnline;plan.LastOnline=&x}
		if err:=validateRefreshPlanOptions(plan,time.Now().UTC());err!=nil{return fail("INVALID_OPTIONS",err)}
		planning=&plan
	}
	// Freeze the supplied checkpoint for all steps of this synchronous call.
	if o.Checkpoint!=nil{c:=*o.Checkpoint;if err:=c.validate();err!=nil{return fail("INVALID_OPTIONS",err)};o.Checkpoint=&c}
	if err:=ctx.Err();err!=nil{return fail("CANCELLED",err)}
	d,err:=DiagnoseState(o.DiagnosticOptions)
	if err!=nil{return fail("DIAGNOSIS_FAILED",err)}
	result.Diagnostic=&d
	if err:=ctx.Err();err!=nil{return fail("CANCELLED",err)}
	if o.Mode==UpdatePlan{
		if planning!=nil{
			// Reuse exactly the diagnosis already performed; never scan twice.
			p,err:=planRefreshFromDiagnostic(*planning,d,o.Authority.SHA256())
			if err!=nil{return fail("PLAN_FAILED",err)}
			if err:=ctx.Err();err!=nil{return fail("CANCELLED",err)}
			result.RefreshPlan=&p
		}
		result.Status="PLAN_ONLY"
		return result,nil,nil
	}

	blocked:=func()(UpdateResult,*ConsumerSession,error){
		return fail("ACTION_BLOCKED",errors.New("explicit action not appropriate for diagnosed state; inspect recommendation"))
	}
	switch o.Mode{
	case UpdateOpen:
		if d.Status!="INSTALLED_EVIDENCE_MATCHES"||d.Installed==nil{return blocked()}
	case UpdateRecoverPending:
		if d.Recommendation!="RECOVER_PENDING_INSTALL"||d.Pending==nil{return blocked()}
	case UpdateRecoverRoot:
		if d.Status!="ROOT_CACHE_BEHIND_ARCHIVE"||d.ArchivedHeadSHA256!=o.ExpectedRootHeadSHA256{return blocked()}
	case UpdateRefresh:
		if d.Recommendation!="VERIFY_FORWARD_REFRESH_WITH_CHECKPOINT"&&d.Status!="INSTALLED_EVIDENCE_MATCHES"{return blocked()}
	}
	if err:=ctx.Err();err!=nil{return fail("CANCELLED",err)}
	result.ActionAttempted=true
	var expected ReleaseCheckpoint
	switch o.Mode{
	case UpdateRecoverRoot:
		r,err:=RecoverRootCache(RootRecoveryOptions{StateDir:o.StateDir,InitialRootSHA256:o.InitialRootSHA256,Authority:o.Authority,ExpectedHeadSHA256:o.ExpectedRootHeadSHA256})
		if err!=nil{return fail("ACTION_FAILED",err)}
		result.RootRecovery=&r;result.ActionCompleted=true
		if err:=ctx.Err();err!=nil{return fail("CANCELLED_AFTER_ACTION",err)}
		result.Status="ROOT_RECOVERED_REFRESH_REQUIRED"
		return result,nil,nil
	case UpdateRecoverPending:
		r,err:=RecoverPendingInstall(RecoveryOptions{StateDir:o.StateDir,InitialRootSHA256:o.InitialRootSHA256,Authority:o.Authority,Checkpoint:o.Checkpoint})
		if err!=nil{return fail("ACTION_FAILED",err)}
		result.Install=&r;result.ActionCompleted=true
		expected=ReleaseCheckpoint{Sequence:r.Registry.Manifest.Sequence,SnapshotSHA256:r.Registry.SnapshotSHA256,RootVersion:r.RootVersion}
	case UpdateRefresh:
		_,r,err:=refresh(ctx,Options{StateDir:o.StateDir,MetadataURL:o.MetadataURL,TargetsURL:o.TargetsURL,InitialRootSHA256:o.InitialRootSHA256,ReviewAuthority:o.Authority,Checkpoint:o.Checkpoint},true,client)
		if err!=nil{return fail("ACTION_FAILED",err)}
		result.Install=&r;result.ActionCompleted=true
		expected=ReleaseCheckpoint{Sequence:r.Registry.Manifest.Sequence,SnapshotSHA256:r.Registry.SnapshotSHA256,RootVersion:r.RootVersion}
	case UpdateOpen:
		expected=ReleaseCheckpoint{Sequence:d.Installed.Sequence,SnapshotSHA256:d.Installed.SnapshotSHA256,RootVersion:d.Installed.RootVersion}
	}
	if err:=ctx.Err();err!=nil{
		if result.ActionCompleted{return fail("CANCELLED_AFTER_ACTION",err)}
		return fail("CANCELLED",err)
	}
	// Bind the reopened session to the exact action result, not just its
	// minimum sequence. A concurrent update between locks cannot substitute
	// another release or a lower root. No session returned on any failure.
	s,err:=OpenConsumer(ConsumerOptions{StateDir:o.StateDir,InitialRootSHA256:o.InitialRootSHA256,Authority:o.Authority,MinimumSequence:expected.Sequence,ExpectedSnapshotSHA256:expected.SnapshotSHA256})
	if err!=nil{return fail("SESSION_OPEN_FAILED",err)}
	info,err:=s.Info();if err!=nil{return fail("SESSION_OPEN_FAILED",err)}
	actual,err:=s.Checkpoint();if err!=nil{return fail("SESSION_OPEN_FAILED",err)}
	if actual!=expected{return fail("SESSION_CHANGED",errors.New("installed release changed between stages"))}
	if o.Checkpoint!=nil{if err:=o.Checkpoint.check(actual.Sequence,actual.SnapshotSHA256,actual.RootVersion);err!=nil{return fail("SESSION_CHECKPOINT_FAILED",err)}}
	if err:=ctx.Err();err!=nil{
		if result.ActionCompleted{return fail("CANCELLED_AFTER_ACTION",err)}
		return fail("CANCELLED",err)
	}
	completed:=time.Now().UTC()
	if err:=s.checkAt(completed);err!=nil{return fail("SESSION_OPEN_FAILED",err)}
	if err:=ctx.Err();err!=nil{
		if result.ActionCompleted{return fail("CANCELLED_AFTER_ACTION",err)}
		return fail("CANCELLED",err)
	}
	// Only a successful explicit online action followed by exact session
	// reopening can issue an observation. Offline opens and recovery cannot.
	if o.Mode==UpdateRefresh{
		result.OnlineObservation=&RefreshObservation{
			InitialRootSHA256:info.InitialRootSHA256,AuthoritySHA256:info.AuthoritySHA256,
			Checkpoint:actual,CompletedAt:completed,
		}
	}
	result.Consumer=&info
	result.Checkpoint=&actual
	result.ActionCompleted=true
	result.Status="CONSUMER_READY"
	return result,s,nil
}
