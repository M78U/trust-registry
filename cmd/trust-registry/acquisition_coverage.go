package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/M78U/trust-registry/pkg/sources"
)

func runAcquisitionCoverage(args []string,out io.Writer)error{
	f:=flag.NewFlagSet("sources acquisition-coverage",flag.ContinueOnError)
	root:=f.String("registry","","initialized private local registry")
	var o sources.AcquisitionArchiveOptions
	f.BoolVar(&o.Technical,"technical",false,"derive technical evidence from explicitly pinned archive CA members")
	f.StringVar(&o.ArchiveDir,"archive","","private endpoint archive directory")
	f.Func("archive-pin","listing-id=independent-sha256 (repeatable)",func(v string)error{
		id,h,ok:=strings.Cut(v,"=");if !ok||id==""||h==""||len(o.Archives)>=sources.MaxCoverageArchives{return errors.New("invalid archive selection")}
		o.Archives=append(o.Archives,sources.AcquisitionArchiveReference{ListingID:id,SHA256:h});return nil
	})
	f.Func("bundle-pin","independent-plan-sha256=private-directory (repeatable)",func(v string)error{
		h,path,ok:=strings.Cut(v,"=");if !ok||h==""||path==""||len(o.Bundles)>=sources.MaxCoverageBundles{return errors.New("invalid bundle selection")}
		o.Bundles=append(o.Bundles,sources.AcquisitionBundleReference{Directory:path,SHA256:h});return nil
	})
	if err:=f.Parse(args);err!=nil{return err}
	if f.NArg()!=0||*root==""{return errors.New("usage: sources acquisition-coverage --registry DIR")}
	s,err:=registry.OpenStore(*root);if err!=nil{return err}
	r,err:=sources.PlanPinnedAcquisitionCoverage(s,o);if err!=nil{return err}
	return json.NewEncoder(out).Encode(r)
}
