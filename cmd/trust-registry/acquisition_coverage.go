package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/M78U/trust-registry/pkg/sources"
)

func runAcquisitionCoverage(args []string,out io.Writer)error{
	f:=flag.NewFlagSet("sources acquisition-coverage",flag.ContinueOnError)
	root:=f.String("registry","","initialized private local registry")
	if err:=f.Parse(args);err!=nil{return err}
	if f.NArg()!=0||*root==""{return errors.New("usage: sources acquisition-coverage --registry DIR")}
	s,err:=registry.OpenStore(*root);if err!=nil{return err}
	r,err:=sources.PlanAcquisitionCoverage(s);if err!=nil{return err}
	return json.NewEncoder(out).Encode(r)
}
