package main

import (
	"context"
	"bytes"
	"os/signal"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	tuf "github.com/M78U/trust-registry/tools/tuf-client"
	"github.com/M78U/trust-registry/pkg/snapshot"
)
func run()error{
	state:=flag.String("state","","private TUF state")
	pin:=flag.String("root-sha256","","independently pinned initial root hash")
	fp:=flag.String("fingerprint","","optional certificate fingerprint")
	authority:=flag.String("authority","","independently provisioned review authority file")
	authorityPin:=flag.String("authority-sha256","","independent authority pin")
	coordinate:=flag.String("coordinate","","strict update mode: plan, open, recover-pending, recover-root, refresh")
	metaURL:=flag.String("metadata-url","","explicit HTTPS metadata URL for coordinated refresh")
	targetsURL:=flag.String("targets-url","","explicit HTTPS targets URL for coordinated refresh")
	diagnose:=flag.Bool("diagnose",false,"inspect strict local state and recommend a recovery action without repair")
	recoverPending:=flag.Bool("recover-pending",false,"finish a strict pending installation offline")
	recoverRoot:=flag.Bool("recover-root-cache",false,"advance cached root to verified archived head offline")
	rootHead:=flag.String("root-head-sha256","","explicit expected archived head digest for root recovery")
	checkpointSequence:=flag.Uint64("checkpoint-sequence",0,"independent strict release sequence")
	checkpointHash:=flag.String("checkpoint-snapshot-sha256","","independent snapshot SHA-256")
	checkpointRoot:=flag.Int64("checkpoint-root-version",0,"independent TUF root version")
	refreshAge:=flag.Duration("refresh-max-age",0,"explicit maximum online observation age (plan only)")
	expiryLead:=flag.Duration("refresh-expiry-lead",0,"explicit signed expiry lead (plan only)")
	lastOnline:=flag.String("last-online-observation","","compact JSON onlineObservation from a successful coordinated refresh (plan only)")
	flag.Parse()
	if flag.NArg()!=0||*state==""||*pin==""{return errors.New("state and root-sha256 required")}
	if (*authority=="")!=(*authorityPin==""){return errors.New("authority and authority-sha256 must be supplied together")}
	checkpointRequested:=false
	flag.Visit(func(f *flag.Flag){switch f.Name{case "checkpoint-sequence","checkpoint-snapshot-sha256","checkpoint-root-version":checkpointRequested=true}})
	var ageSet,leadSet,observationSet bool
	flag.Visit(func(f *flag.Flag){switch f.Name{case "refresh-max-age":ageSet=true;case "refresh-expiry-lead":leadSet=true;case "last-online-observation":observationSet=true}})
	planningRequested:=ageSet||leadSet||observationSet
	if planningRequested&&(*coordinate!="plan"||!ageSet||!leadSet){return errors.New("refresh planning flags require coordinate plan and both explicit duration flags")}
	if *coordinate!=""{
		if *diagnose||*recoverPending||*recoverRoot||*fp!=""||*authority==""{return errors.New("coordinate requires strict authority and no separate operation flags")}
		a,err:=tuf.LoadReviewAuthority(*authority,*authorityPin);if err!=nil{return err}
		o:=tuf.CoordinateOptions{DiagnosticOptions:tuf.DiagnosticOptions{StateDir:*state,InitialRootSHA256:*pin,Authority:a},Mode:tuf.UpdateMode(*coordinate),ExpectedRootHeadSHA256:*rootHead,MetadataURL:*metaURL,TargetsURL:*targetsURL}
		if checkpointRequested{
			if *checkpointSequence==0||*checkpointHash==""||*checkpointRoot<1{return errors.New("all three checkpoint flags required together")}
			o.Checkpoint=&tuf.ReleaseCheckpoint{Sequence:*checkpointSequence,SnapshotSHA256:*checkpointHash,RootVersion:*checkpointRoot}
		}
		if planningRequested{
			o.RefreshPolicy=&tuf.RefreshPlanningPolicy{MaxOnlineAge:*refreshAge,ExpiryLead:*expiryLead}
			if observationSet{
				x,err:=parseOnlineObservation(*lastOnline);if err!=nil{return err}
				o.RefreshPolicy.LastOnline=&x
			}
		}
		ctx,cancel:=signal.NotifyContext(context.Background(),os.Interrupt);defer cancel()
		r,_,err:=tuf.CoordinateUpdate(ctx,o)
		if e:=json.NewEncoder(os.Stdout).Encode(r);e!=nil{return e}
		return err
	}
	if *metaURL!=""||*targetsURL!=""{return errors.New("repository URLs require coordinated refresh")}
	if *diagnose{
		if *recoverRoot||*recoverPending||*rootHead!=""||*fp!=""||*authority==""{return errors.New("diagnose requires strict authority and no recovery or fingerprint flags")}
		a,err:=tuf.LoadReviewAuthority(*authority,*authorityPin);if err!=nil{return err}
		o:=tuf.DiagnosticOptions{StateDir:*state,InitialRootSHA256:*pin,Authority:a}
		if checkpointRequested{
			if *checkpointSequence==0||*checkpointHash==""||*checkpointRoot<1{return errors.New("all three checkpoint flags required together")}
			o.Checkpoint=&tuf.ReleaseCheckpoint{Sequence:*checkpointSequence,SnapshotSHA256:*checkpointHash,RootVersion:*checkpointRoot}
		}
		r,err:=tuf.DiagnoseState(o);if err!=nil{return err}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	if *recoverRoot{
		if *recoverPending||checkpointRequested||*authority==""||*fp!=""||*rootHead==""{return errors.New("recover-root-cache requires strict authority and root-head-sha256; no other recovery, checkpoint or fingerprint flags")}
		a,err:=tuf.LoadReviewAuthority(*authority,*authorityPin);if err!=nil{return err}
		r,err:=tuf.RecoverRootCache(tuf.RootRecoveryOptions{StateDir:*state,InitialRootSHA256:*pin,Authority:a,ExpectedHeadSHA256:*rootHead});if err!=nil{return err}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	if *rootHead!=""{return errors.New("root-head-sha256 requires recover-root-cache")}
	if checkpointRequested&&!*recoverPending{return errors.New("checkpoint flags require diagnose or recover-pending")}
	if *recoverPending{
		if *authority==""||*fp!=""{return errors.New("recover-pending requires strict authority and no fingerprint")}
		a,err:=tuf.LoadReviewAuthority(*authority,*authorityPin);if err!=nil{return err}
		o:=tuf.RecoveryOptions{StateDir:*state,InitialRootSHA256:*pin,Authority:a}
		if checkpointRequested{
			if *checkpointSequence==0||*checkpointHash==""||*checkpointRoot<1{return errors.New("all three checkpoint flags required together")}
			o.Checkpoint=&tuf.ReleaseCheckpoint{Sequence:*checkpointSequence,SnapshotSHA256:*checkpointHash,RootVersion:*checkpointRoot}
		}
		r,err:=tuf.RecoverPendingInstall(o);if err!=nil{return err}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	var v *snapshot.Loaded;var r tuf.Report;var err error
	if *authority!=""{a,e:=tuf.LoadReviewAuthority(*authority,*authorityPin);if e!=nil{return e};v,r,err=tuf.LoadAuthorizedInstalled(*state,*pin,a)}else{v,r,err=tuf.LoadInstalled(*state,*pin)}
	if err!=nil{return err}
	if *fp==""{return json.NewEncoder(os.Stdout).Encode(r)}
	record,err:=v.Find(*fp);if err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(struct{Report tuf.Report `json:"report"`; Certificate any `json:"certificate"`}{r,record})
}
// Accept only the compact exact JSON representation emitted by the SDK.
 // Re-encoding rejects unknown, duplicate, omitted and reordered fields.
func parseOnlineObservation(raw string)(tuf.RefreshObservation,error){
	var x tuf.RefreshObservation
	if len(raw)==0||len(raw)>4096||json.Unmarshal([]byte(raw),&x)!=nil{return x,errors.New("invalid online observation JSON")}
	canonical,err:=json.Marshal(x)
	if err!=nil||!bytes.Equal(canonical,[]byte(raw)){return tuf.RefreshObservation{},errors.New("online observation must be exact compact SDK JSON")}
	return x,nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
