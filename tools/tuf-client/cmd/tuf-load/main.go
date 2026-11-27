package main

import (
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
	recoverPending:=flag.Bool("recover-pending",false,"finish a strict pending installation offline")
	recoverRoot:=flag.Bool("recover-root-cache",false,"advance cached root to verified archived head offline")
	rootHead:=flag.String("root-head-sha256","","explicit expected archived head digest for root recovery")
	checkpointSequence:=flag.Uint64("checkpoint-sequence",0,"independent strict release sequence")
	checkpointHash:=flag.String("checkpoint-snapshot-sha256","","independent snapshot SHA-256")
	checkpointRoot:=flag.Int64("checkpoint-root-version",0,"independent TUF root version")
	flag.Parse()
	if flag.NArg()!=0||*state==""||*pin==""{return errors.New("state and root-sha256 required")}
	if (*authority=="")!=(*authorityPin==""){return errors.New("authority and authority-sha256 must be supplied together")}
	checkpointRequested:=false
	flag.Visit(func(f *flag.Flag){switch f.Name{case "checkpoint-sequence","checkpoint-snapshot-sha256","checkpoint-root-version":checkpointRequested=true}})
	if *recoverRoot{
		if *recoverPending||checkpointRequested||*authority==""||*fp!=""||*rootHead==""{return errors.New("recover-root-cache requires strict authority and root-head-sha256; no other recovery, checkpoint or fingerprint flags")}
		a,err:=tuf.LoadReviewAuthority(*authority,*authorityPin);if err!=nil{return err}
		r,err:=tuf.RecoverRootCache(tuf.RootRecoveryOptions{StateDir:*state,InitialRootSHA256:*pin,Authority:a,ExpectedHeadSHA256:*rootHead});if err!=nil{return err}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	if *rootHead!=""{return errors.New("root-head-sha256 requires recover-root-cache")}
	if checkpointRequested&&!*recoverPending{return errors.New("checkpoint flags require recover-pending")}
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
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
