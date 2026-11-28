//go:build maintainer

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/M78U/trust-registry/pkg/sources"
)

func runSourceMonitor(args []string,out io.Writer)error {
	enc:=json.NewEncoder(out)
	if args[0]=="monitor-list" {
		if len(args)!=1 { return errors.New("usage: sources monitor-list") }
		return enc.Encode(sources.MonitorSources())
	}
	f:=flag.NewFlagSet("sources "+args[0],flag.ContinueOnError)
	if args[0]=="monitor-diff" {
		before:=f.String("previous-sha256","","independently retained previous observation SHA-256")
		after:=f.String("current-sha256","","independently retained current observation SHA-256")
		if err:=f.Parse(args[1:]);err!=nil{return err}
		if f.NArg()!=2||*before==""||*after==""{return errors.New("usage: sources monitor-diff --previous-sha256 PIN --current-sha256 PIN PREVIOUS CURRENT")}
		a,err:=readSmall(f.Arg(0),sources.MaxSourceObservationBytes);if err!=nil{return err}
		b,err:=readSmall(f.Arg(1),sources.MaxSourceObservationBytes);if err!=nil{return err}
		r,err:=sources.CompareSourceObservations(a,*before,b,*after);if err!=nil{return err}
		return enc.Encode(r)
	}
	id:=f.String("id","","explicit monitor source ID")
	dest:=f.String("out","","new private observation file")
	var at string
	if args[0]=="monitor-local"{f.StringVar(&at,"recorded-at","","explicit local observation time RFC3339")}
	if err:=f.Parse(args[1:]);err!=nil{return err}
	if *id==""||*dest==""{return errors.New("source ID and new private output file required")}
	if _,err:=os.Lstat(*dest);err==nil{return errors.New("output already exists")}else if !os.IsNotExist(err){return err}
	var raw []byte
	var r sources.SourceObservationReceipt
	var err error
	switch args[0]{
	case "monitor-fetch":
		if f.NArg()!=0{return errors.New("usage: sources monitor-fetch --id ID --out NEW_FILE")}
		raw,r,err=sources.FetchSourceObservation(context.Background(),*id)
	case "monitor-local":
		if f.NArg()!=1||at==""{return errors.New("usage: sources monitor-local --id ID --recorded-at RFC3339 --out NEW_FILE FILE")}
		t,e:=time.Parse(time.RFC3339Nano,at);if e!=nil{return e}
		input,e:=readSmall(f.Arg(0),sources.MaxSourceBodyBytes);if e!=nil{return e}
		raw,r,err=sources.ObserveLocalSource(*id,input,t.UTC())
	default:return errors.New("unknown monitor command")
	}
	if err!=nil{return err}
	if err:=writeNew(*dest,raw);err!=nil{return err}
	return enc.Encode(r)
}
