package tufclient

import (
	"strings"
	"testing"
	"time"
)

func refreshPlanFixture() (RefreshPlanOptions, StateDiagnostic, string) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	root, authority, snapshot := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	o := RefreshPlanOptions{
		DiagnosticOptions: DiagnosticOptions{InitialRootSHA256: root},
		MaxOnlineAge: 2*time.Hour,
		ExpiryLead: 30*time.Minute,
		LastOnline: &RefreshObservation{InitialRootSHA256: root, AuthoritySHA256: authority, Checkpoint: ReleaseCheckpoint{Sequence: 2, SnapshotSHA256: snapshot, RootVersion: 1}, CompletedAt: now.Add(-time.Hour)},
	}
	d := StateDiagnostic{Status: "INSTALLED_EVIDENCE_MATCHES", CheckedAt: now, Installed: &DiagnosticEvidence{Sequence: 2, SnapshotSHA256: snapshot, RootVersion: 1, ValidUntil: now.Add(3*time.Hour), CacheMatches: true, CheckpointMatches: true}}
	return o, d, authority
}

func TestRefreshPlanAdvisory(t *testing.T) {
	for _, tc := range []struct {
		name string
		change func(*RefreshPlanOptions, *StateDiagnostic)
		status string
		suggested, matched bool
	}{
		{"not due", func(o *RefreshPlanOptions,d *StateDiagnostic){}, "NOT_DUE_UNDER_LOCAL_POLICY", false, true},
		{"age equality", func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline.CompletedAt=d.CheckedAt.Add(-o.MaxOnlineAge)}, "ONLINE_AGE_DUE", true,true},
		{"expiry lead equality", func(o *RefreshPlanOptions,d *StateDiagnostic){d.Installed.ValidUntil=d.CheckedAt.Add(o.ExpiryLead)}, "SIGNED_EXPIRY_APPROACHING",true,true},
		{"missing observation", func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline=nil}, "ONLINE_OBSERVATION_REQUIRED",true,false},
		{"different release", func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline.Checkpoint.Sequence++}, "ONLINE_OBSERVATION_REQUIRED",true,false},
		{"different authority", func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline.AuthoritySHA256=strings.Repeat("d",64)}, "ONLINE_OBSERVATION_REQUIRED",true,false},
		{"different root", func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline.InitialRootSHA256=strings.Repeat("d",64)}, "ONLINE_OBSERVATION_REQUIRED",true,false},
		{"different root version", func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline.Checkpoint.RootVersion++}, "ONLINE_OBSERVATION_REQUIRED",true,false},
		{"expired", func(o *RefreshPlanOptions,d *StateDiagnostic){d.Status="INSTALLED_EXPIRED";d.Installed.Expired=true}, "DIAGNOSTIC_ACTION_REQUIRED",false,false},
		{"busy", func(o *RefreshPlanOptions,d *StateDiagnostic){d.Status="STATE_LOCKED";d.Installed=nil}, "DIAGNOSTIC_ACTION_REQUIRED",false,false},
		{"pending", func(o *RefreshPlanOptions,d *StateDiagnostic){d.Status="PENDING_RECOVERY_CANDIDATE"}, "DIAGNOSTIC_ACTION_REQUIRED",false,false},
	} {
		t.Run(tc.name,func(t *testing.T){
			o,d,a:=refreshPlanFixture()
			tc.change(&o,&d)
			p,err:=planRefreshFromDiagnostic(o,d,a)
			if err!=nil || p.Status!=tc.status || p.RefreshSuggested!=tc.suggested || p.ObservationMatched!=tc.matched || p.TrustStatus!="NOT_ESTABLISHED" || p.Diagnostic.Status!=d.Status {
				t.Fatalf("unexpected plan: %+v %v",p,err)
			}
			if (p.NextCheckAt!=nil)!=tc.matched { t.Fatal("unexpected next check") }
			if tc.name=="not due" && !p.NextCheckAt.Equal(d.CheckedAt.Add(time.Hour)) { t.Fatal("incorrect age deadline") }
		})
	}
}

func TestRefreshPlanInvalidInputs(t *testing.T) {
	for _, change := range []func(*RefreshPlanOptions,*StateDiagnostic){
		func(o *RefreshPlanOptions,d *StateDiagnostic){o.MaxOnlineAge=0},
		func(o *RefreshPlanOptions,d *StateDiagnostic){o.MaxOnlineAge=31*24*time.Hour},
		func(o *RefreshPlanOptions,d *StateDiagnostic){o.ExpiryLead=-time.Second},
		func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline.CompletedAt=d.CheckedAt.Add(time.Second)},
		func(o *RefreshPlanOptions,d *StateDiagnostic){o.LastOnline.Checkpoint.SnapshotSHA256="invalid"},
		func(o *RefreshPlanOptions,d *StateDiagnostic){d.Installed=nil},
		func(o *RefreshPlanOptions,d *StateDiagnostic){d.Installed.ValidUntil=d.CheckedAt},
		func(o *RefreshPlanOptions,d *StateDiagnostic){d.Installed.CheckpointMatches=false},
	} {
		o,d,a:=refreshPlanFixture()
		change(&o,&d)
		if _,err:=planRefreshFromDiagnostic(o,d,a);err==nil{t.Fatal("accepted invalid planning input")}
	}
}
