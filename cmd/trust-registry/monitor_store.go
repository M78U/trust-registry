package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/M78U/trust-registry/pkg/sources"
)

func runMonitorStore(args []string,out io.Writer)error{
	f:=flag.NewFlagSet("sources "+args[0],flag.ContinueOnError)
	root:=f.String("store","","existing private monitor store directory")
	var id,mode,pin,at string
	var interval time.Duration
	switch args[0]{
	case "monitor-add":
		f.StringVar(&pin,"sha256","","independent observation pin")
	case "monitor-history","monitor-verify":
		f.StringVar(&id,"id","","monitor source ID")
		f.StringVar(&mode,"mode","HTTPS_RESPONSE","observation mode")
		if args[0]=="monitor-verify"{f.StringVar(&pin,"sha256","","independent observation pin")}
	case "monitor-plan":
		f.StringVar(&mode,"mode","HTTPS_RESPONSE","observation mode")
		f.StringVar(&at,"at","","explicit evaluation time RFC3339")
		f.DurationVar(&interval,"interval",0,"explicit check interval 1h to 30d")
	default:return errors.New("unknown monitor store command")
	}
	if err:=f.Parse(args[1:]);err!=nil{return err}
	if *root==""{return errors.New("existing private --store directory required")}
	enc:=json.NewEncoder(out)
	switch args[0]{
	case "monitor-add":
		if f.NArg()!=1||pin==""{return errors.New("usage: sources monitor-add --store DIR --sha256 PIN OBSERVATION")}
		b,err:=readSmall(f.Arg(0),sources.MaxSourceObservationBytes);if err!=nil{return err}
		r,err:=sources.AddMonitorObservation(*root,b,pin);if err!=nil{return err}
		return enc.Encode(r)
	case "monitor-history":
		if f.NArg()!=0||id==""{return errors.New("usage: sources monitor-history --store DIR --id ID [--mode MODE]")}
		r,err:=sources.ReadMonitorHistory(*root,id,mode);if err!=nil{return err}
		return enc.Encode(r)
	case "monitor-verify":
		if f.NArg()!=0||id==""||pin==""{return errors.New("usage: sources monitor-verify --store DIR --id ID --sha256 PIN [--mode MODE]")}
		r,err:=sources.VerifyMonitorRecord(*root,id,mode,pin);if err!=nil{return err}
		return enc.Encode(r)
	case "monitor-plan":
		if f.NArg()!=0||at==""{return errors.New("usage: sources monitor-plan --store DIR --at RFC3339 --interval DURATION [--mode MODE]")}
		t,err:=time.Parse(time.RFC3339Nano,at);if err!=nil{return err}
		r,err:=sources.PlanMonitorChecks(*root,mode,t.UTC(),interval);if err!=nil{return err}
		return enc.Encode(r)
	}
	return errors.New("unknown monitor store command")
}
