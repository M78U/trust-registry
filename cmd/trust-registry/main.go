package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
)

func readInput(path string) ([]byte, error) {
	info,err:=os.Lstat(path)
	if err!=nil { return nil,err }
	if !info.Mode().IsRegular() { return nil,errors.New("expected regular file") }
	f,err:=os.Open(path)
	if err!=nil { return nil,err }
	defer f.Close()
	opened,err:=f.Stat()
	if err!=nil { return nil,err }
	if !opened.Mode().IsRegular() || !os.SameFile(info,opened) { return nil,errors.New("file changed while opening") }
	data,err:=io.ReadAll(io.LimitReader(f,registry.MaxCertificateInput+1))
	if err!=nil { return nil,err }
	if len(data)>registry.MaxCertificateInput { return nil,errors.New("certificate input too large") }
	return data,nil
}

func run(args []string,out io.Writer) error {
	if len(args)==0 { return errors.New("usage: trust-registry inspect FILE | import | list | find | provenance | validate | discover") }
	if args[0]=="inspect" {
		if len(args)!=2 { return errors.New("usage: inspect FILE") }
		input,err:=readInput(args[1])
		if err!=nil { return err }
		record,_,err:=registry.ParseCertificate(input)
		if err!=nil { return err }
		return json.NewEncoder(out).Encode(record)
	}
	flags:=flag.NewFlagSet(args[0],flag.ContinueOnError)
	root:=flags.String("registry","registry","local inventory directory")
	encode:=json.NewEncoder(out)
	switch args[0] {
	case "import":
		source:=flags.String("source","","asserted public HTTPS source URL (not fetched)")
		if err:=flags.Parse(args[1:]); err!=nil { return err }
		if flags.NArg()!=1 { return errors.New("usage: import [--registry DIR] --source HTTPS_URL FILE") }
		input,err:=readInput(flags.Arg(0))
		if err!=nil { return err }
		s,err:=registry.OpenStore(*root)
		if err!=nil { return err }
		result,err:=s.Import(input,*source,time.Now())
		if err!=nil { return err }
		return encode.Encode(result)
	case "discover":
		if err:=flags.Parse(args[1:]); err!=nil { return err }
		if flags.NArg()!=1 { return errors.New("usage: discover [--registry DIR] FILE") }
		input,err:=readInput(flags.Arg(0))
		if err!=nil { return err }
		s,err:=registry.OpenStore(*root)
		if err!=nil { return err }
		report,err:=s.DiscoverIssuers(input)
		if err!=nil { return err }
		return encode.Encode(report)
	case "list","validate":
		if err:=flags.Parse(args[1:]); err!=nil { return err }
		if flags.NArg()!=0 { return errors.New("unexpected positional arguments") }
		s,err:=registry.OpenStore(*root)
		if err!=nil { return err }
		if args[0]=="list" {
			records,err:=s.List()
			if err!=nil { return err }
			return encode.Encode(records)
		}
		report,err:=s.Validate()
		if err!=nil { return err }
		return encode.Encode(report)
	case "find","provenance":
		fp:=flags.String("fingerprint","","lowercase SHA-256 DER fingerprint")
		if err:=flags.Parse(args[1:]); err!=nil { return err }
		if flags.NArg()!=0 || *fp=="" { return errors.New("expected --fingerprint SHA256") }
		s,err:=registry.OpenStore(*root)
		if err!=nil { return err }
		if args[0]=="find" {
			record,err:=s.Find(*fp)
			if err!=nil { return err }
			return encode.Encode(record)
		}
		records,err:=s.Provenance(*fp)
		if err!=nil { return err }
		return encode.Encode(records)
	default:
		return errors.New("unknown command")
	}
}

func main() {
	if err:=run(os.Args[1:],os.Stdout); err!=nil {
		fmt.Fprintln(os.Stderr,err)
		os.Exit(1)
	}
}
