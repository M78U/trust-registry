package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/M78U/trust-registry/tools/tuf-client"
)

func run()error{
	state:=flag.String("state","","private TUF state directory")
	meta:=flag.String("metadata-url","","HTTPS metadata base")
	targets:=flag.String("targets-url","","HTTPS targets base")
	pin:=flag.String("root-sha256","","independently obtained initial root SHA-256")
	root:=flag.String("bootstrap-root","","independently obtained root.json for first use")
	out:=flag.String("out","","new local snapshot output file")
	install:=flag.Bool("install",false,"install verified snapshot and evidence into state")
	authority:=flag.String("authority","","independently provisioned review authority file")
	authorityPin:=flag.String("authority-sha256","","independent authority pin; enables strict mode")
	checkpointSequence:=flag.Uint64("checkpoint-sequence",0,"independently retained strict release sequence")
	checkpointHash:=flag.String("checkpoint-snapshot-sha256","","independently retained snapshot SHA-256")
	checkpointRoot:=flag.Int64("checkpoint-root-version",0,"independently retained TUF root version")
	flag.Parse()
	if flag.NArg()!=0||*state==""||*meta==""||*targets==""||*pin==""||(*out=="")==(!*install){return errors.New("state, metadata-url, targets-url, root-sha256 and exactly one of out/install required")}
	if *out!=""{if _,err:=os.Lstat(*out);err==nil{return errors.New("output exists")}else if !os.IsNotExist(err){return err}}
	o:=tufclient.Options{StateDir:*state,MetadataURL:*meta,TargetsURL:*targets,InitialRootSHA256:*pin}
	if (*authority=="")!=(*authorityPin==""){return errors.New("authority and authority-sha256 must be supplied together")}
	if *authority!=""{a,err:=tufclient.LoadReviewAuthority(*authority,*authorityPin);if err!=nil{return err};o.ReviewAuthority=a}
	if *checkpointSequence!=0||*checkpointHash!=""||*checkpointRoot!=0{
		if o.ReviewAuthority==nil||*checkpointSequence==0||*checkpointHash==""||*checkpointRoot<1{return errors.New("strict authority and all three checkpoint flags required together")}
		o.Checkpoint=&tufclient.ReleaseCheckpoint{Sequence:*checkpointSequence,SnapshotSHA256:*checkpointHash,RootVersion:*checkpointRoot}
	}
	if *root!=""{
		i,err:=os.Lstat(*root);if err!=nil{return err}
		if !i.Mode().IsRegular()||i.Size()>512000{return errors.New("invalid bootstrap root file")}
		f,err:=os.Open(*root);if err!=nil{return err};defer f.Close()
		s,err:=f.Stat();if err!=nil{return err}
		if !os.SameFile(i,s){return errors.New("root file changed")}
		o.BootstrapRoot,err=io.ReadAll(io.LimitReader(f,512001));if err!=nil{return err}
	}
	if *install{report,err:=tufclient.RefreshAndInstall(context.Background(),o);if err!=nil{return err};return json.NewEncoder(os.Stdout).Encode(report)}
	raw,report,err:=tufclient.Refresh(context.Background(),o);if err!=nil{return err}
	f,err:=os.OpenFile(*out,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
	if _,err=f.Write(raw);err==nil{err=f.Sync()}
	closeErr:=f.Close();if err==nil{err=closeErr}
	if err!=nil{_ = os.Remove(*out);return err}
	return json.NewEncoder(os.Stdout).Encode(report)
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
