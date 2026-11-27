package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/M78U/trust-registry/pkg/sources"
)

func runMonitorChecks(args []string,out io.Writer)error{
	f:=flag.NewFlagSet("sources monitor-run",flag.ContinueOnError)
	var o sources.MonitorRunOptions
	f.StringVar(&o.Store,"store","","existing private monitor directory")
	f.DurationVar(&o.Interval,"interval",0,"explicit check interval 1h to 30d")
	f.IntVar(&o.MaxFetches,"max-fetches",0,"explicit per-run request budget")
	f.Func("id","selected fixed source ID (repeatable)",func(id string)error{
		if len(o.IDs)>=len(sources.MonitorSources()){return errors.New("too many selected sources")}
		o.IDs=append(o.IDs,id);return nil
	})
	if err:=f.Parse(args);err!=nil{return err}
	if f.NArg()!=0{return errors.New("usage: sources monitor-run --store DIR --interval DURATION --max-fetches N --id ID")}
	r,err:=sources.RunMonitorChecks(context.Background(),o)
	if r.Status!=""{
		if e:=json.NewEncoder(out).Encode(r);e!=nil{return e}
	}
	return err
}
