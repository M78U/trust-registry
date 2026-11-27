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
	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/validation"
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
	if len(args)==0 { return errors.New("usage: trust-registry init | inspect FILE | import | list | find | provenance | validate | discover | search | policy") }
	if args[0]=="policy" { return runPolicy(args[1:],out) }
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
	case "init":
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=0{return errors.New("usage: init --registry DIR")}
		s,err:=registry.OpenStore(*root);if err!=nil{return err}
		report,err:=s.Init();if err!=nil{return err}
		return encode.Encode(report)
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
	case "search":
		var q registry.Query
		flags.StringVar(&q.Fingerprint,"fingerprint","","exact lowercase SHA-256")
		flags.StringVar(&q.Subject,"subject","","exact subject display DN")
		flags.StringVar(&q.Issuer,"issuer","","exact issuer display DN")
		flags.StringVar(&q.Serial,"serial","","positive hexadecimal serial")
		flags.StringVar(&q.SKI,"ski","","lowercase hexadecimal SKI")
		flags.StringVar(&q.AKI,"aki","","lowercase hexadecimal AKI")
		flags.StringVar(&q.PublicKeyAlgorithm,"key-algorithm","","exact public key algorithm")
		flags.StringVar(&q.SignatureAlgorithm,"signature-algorithm","","exact signature algorithm")
		flags.StringVar(&q.SourceHost,"source-host","","asserted source hostname")
		flags.StringVar(&q.After,"after","","exclusive fingerprint cursor")
		flags.IntVar(&q.Limit,"limit",registry.DefaultSearchLimit,"maximum results (1–1000)")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=0 || q.Limit<1 {return errors.New("invalid search arguments")}
		s,err:=registry.OpenStore(*root);if err!=nil{return err}
		idx,err:=s.BuildIndex();if err!=nil{return err}
		result,err:=idx.Search(q);if err!=nil{return err}
		return encode.Encode(result)
	case "validate":
		var paths []string
		flags.Func("policy","policy review JSON file (repeatable)",func(path string)error{
			if path=="" || len(paths)>=validation.MaxPolicyDocuments{return errors.New("invalid policy path or document limit exceeded")};paths=append(paths,path);return nil
		})
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=0{return errors.New("unexpected positional arguments")}
		s,err:=registry.OpenStore(*root);if err!=nil{return err}
		if len(paths)==0{report,err:=s.Validate();if err!=nil{return err};return encode.Encode(report)}
		docs:=make([]policy.Document,0,len(paths))
		for _,path:=range paths{d,err:=policy.LoadDocument(path);if err!=nil{return fmt.Errorf("policy %s: %w",path,err)};docs=append(docs,d)}
		report,err:=validation.Validate(s,docs);if err!=nil{return err};return encode.Encode(report)
	case "list":
		if err:=flags.Parse(args[1:]); err!=nil { return err }
		if flags.NArg()!=0 { return errors.New("unexpected positional arguments") }
		s,err:=registry.OpenStore(*root)
		if err!=nil { return err }
		records,err:=s.List()
		if err!=nil { return err }
		return encode.Encode(records)
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

func runPolicy(args []string,out io.Writer) error {
	if len(args)==0 { return errors.New("usage: policy list | inspect ID | evaluate --file FILE --at RFC3339 --known-at RFC3339") }
	enc:=json.NewEncoder(out)
	switch args[0] {
	case "list":
		if len(args)!=1 { return errors.New("usage: policy list") }
		return enc.Encode(policy.Defaults())
	case "inspect":
		if len(args)!=2 { return errors.New("usage: policy inspect ID") }
		for _,p:=range policy.Defaults() { if p.ID==args[1] { return enc.Encode(p) } }
		return errors.New("unknown built-in policy")
	case "evaluate":
		flags:=flag.NewFlagSet("policy evaluate",flag.ContinueOnError)
		file:=flags.String("file","","local policy review document (unauthenticated)")
		root:=flags.String("registry","registry","local inventory directory")
		at:=flags.String("at","","explicit evaluation time RFC3339")
		known:=flags.String("known-at","","explicit knowledge cutoff RFC3339")
		if err:=flags.Parse(args[1:]);err!=nil { return err }
		if flags.NArg()!=0 || *file=="" || *at=="" || *known=="" { return errors.New("file, at and known-at required") }
		e,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil { return err }
		k,err:=time.Parse(time.RFC3339Nano,*known);if err!=nil { return err }
		d,err:=policy.LoadDocument(*file);if err!=nil { return err }
		s,err:=registry.OpenStore(*root);if err!=nil { return err }
		result,err:=d.Evaluate(s,e.UTC(),k.UTC());if err!=nil { return err }
		return enc.Encode(result)
	default:return errors.New("unknown policy command")
	}
}
