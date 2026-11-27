package main

import (
	"context"
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
	"github.com/M78U/trust-registry/pkg/sources"
	"github.com/M78U/trust-registry/pkg/revocation"
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
	if len(args)==0 { return errors.New("usage: trust-registry init | inspect FILE | import | list | find | provenance | validate | discover | aia | graph | paths | verify-path | search | lifecycle | revocation | revocation-store | policy | sources | snapshot | review") }
	if args[0]=="review" { return runReview(args[1:],out) }
	if args[0]=="aia" { return runAIA(args[1:],out) }
	if args[0]=="revocation-store" { return runRevocationStore(args[1:],out) }
	if args[0]=="revocation" { return runRevocation(args[1:],out) }
	if args[0]=="snapshot" { return runSnapshot(args[1:],out) }
	if args[0]=="policy" { return runPolicy(args[1:],out) }
	if args[0]=="sources" { return runSources(args[1:],out) }
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
	case "graph","paths":
		certificate:=flags.String("certificate","","optional ephemeral DER/PEM certificate")
		fp:=flags.String("fingerprint","","start fingerprint for paths")
		depth:=flags.Int("max-depth",registry.MaxPathDepth,"maximum path depth (nodes)")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=0{return errors.New("unexpected positional arguments")}
		var input []byte
		if *certificate!=""{var err error;input,err=readInput(*certificate);if err!=nil{return err};if len(input)==0{return errors.New("empty certificate")}}
		if args[0]=="graph"&&(*fp!=""||*depth!=registry.MaxPathDepth){return errors.New("fingerprint and max-depth are paths options")}
		if args[0]=="paths"&&*fp==""{
			if input==nil{return errors.New("paths requires --fingerprint or --certificate")}
			record,_,err:=registry.ParseCertificate(input);if err!=nil{return err}
			*fp=record.FingerprintSHA256
		}
		s,err:=registry.OpenStore(*root);if err!=nil{return err}
		g,err:=s.BuildGraph(input);if err!=nil{return err}
		if args[0]=="graph"{report,err:=g.Export();if err!=nil{return err};return encode.Encode(report)}
		report,err:=g.Paths(*fp,*depth);if err!=nil{return err}
		return encode.Encode(report)
	case "lifecycle":
		at:=flags.String("at","","explicit evaluation time RFC3339")
		days:=flags.Int("warning-days",90,"expiry warning horizon in UTC days (0..365)")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=0||*at==""{return errors.New("usage: lifecycle --registry DIR --at RFC3339 [--warning-days N]")}
		when,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
		s,err:=registry.OpenStore(*root);if err!=nil{return err}
		r,err:=s.Lifecycle(registry.LifecycleOptions{At:when.UTC(),WarningDays:*days});if err!=nil{return err}
		return encode.Encode(r)
	case "verify-path":
		file:=flags.String("policy","","local policy review JSON")
		purpose:=flags.String("purpose","","explicit requested policy purpose")
		at:=flags.String("at","","evaluation time RFC3339")
		known:=flags.String("known-at","","knowledge cutoff RFC3339")
		dns:=flags.String("dns-name","","server authentication DNS name")
		evidenceDir:=flags.String("revocation-store","","optional private offline evidence store")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=1||*file==""||*purpose==""||*at==""||*known==""{return errors.New("usage: verify-path --policy FILE --purpose PURPOSE --at RFC3339 --known-at RFC3339 CERT")}
		e,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
		k,err:=time.Parse(time.RFC3339Nano,*known);if err!=nil{return err}
		d,err:=policy.LoadDocument(*file);if err!=nil{return err}
		input,err:=readInput(flags.Arg(0));if err!=nil{return err}
		s,err:=registry.OpenStore(*root);if err!=nil{return err}
		if *evidenceDir!=""{
			store,err:=revocation.OpenEvidenceStore(*evidenceDir);if err!=nil{return err}
			result,err:=validation.VerifyLocalPathWithRevocation(s,d,input,*purpose,*dns,e.UTC(),k.UTC(),store);if err!=nil{return err}
			if err:=encode.Encode(result);err!=nil{return err}
			if result.Path.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"||result.Revocation.Status!="NON_REVOKED_INDICATIONS_ONLY"||result.Revocation.HistoricalRevokedIndication{return errors.New("path or supplied revocation evidence incomplete or indicates risk")}
			return nil
		}
		report,err:=validation.VerifyLocalPath(s,d,input,*purpose,*dns,e.UTC(),k.UTC());if err!=nil{return err}
		if err:=encode.Encode(report);err!=nil{return err}
		if report.Path.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"{return errors.New("no valid path under explicit local CA set")}
		return nil
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
	if len(args)==0 { return errors.New("usage: policy list | inspect ID | evaluate | history | restrict | check-transition") }
	enc:=json.NewEncoder(out)
	switch args[0] {
	case "restrict","check-transition":return runPolicyChange(args,out)
	case "list":
		if len(args)!=1 { return errors.New("usage: policy list") }
		return enc.Encode(policy.Defaults())
	case "inspect":
		if len(args)!=2 { return errors.New("usage: policy inspect ID") }
		for _,p:=range policy.Defaults() { if p.ID==args[1] { return enc.Encode(p) } }
		return errors.New("unknown built-in policy")
	case "evaluate","history":
		flags:=flag.NewFlagSet("policy "+args[0],flag.ContinueOnError)
		fp:=flags.String("fingerprint","","history anchor fingerprint")
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
		if args[0]=="history"{
			if *fp==""{return errors.New("history requires --fingerprint")}
			result,err:=d.History(s,*fp,e.UTC(),k.UTC());if err!=nil{return err}
			return enc.Encode(result)
		}
		if *fp!=""{return errors.New("fingerprint is a history option")}
		result,err:=d.Evaluate(s,e.UTC(),k.UTC());if err!=nil { return err }
		return enc.Encode(result)
	default:return errors.New("unknown policy command")
	}
}

func runSources(args []string,out io.Writer)error{
	if len(args)==0{return errors.New("usage: sources list | inspect ID | preview | endpoints | audit | fetch | research | satl | intake-plan | intake-apply | multi-ca | multi-ca-audit | bundle-plan | bundle-export | bundle-apply")}
	if args[0]=="intake-plan"||args[0]=="intake-apply"{return runSourceIntake(args,out)}
	if args[0]=="multi-ca"||args[0]=="multi-ca-audit"{return runMultiCA(args,out)}
	if args[0]=="bundle-plan"||args[0]=="bundle-export"||args[0]=="bundle-apply"{return runBundle(args,out)}
	c,err:=sources.SHECA();if err!=nil{return err}
	enc:=json.NewEncoder(out)
	switch args[0]{
	case "list":
		if len(args)!=1{return errors.New("usage: sources list")}
		return enc.Encode(c)
	case "inspect":
		if len(args)!=2{return errors.New("usage: sources inspect ID")}
		e,err:=c.Find(args[1]);if err!=nil{return err}
		return enc.Encode(e)
	case "satl":
		if len(args)!=1{return errors.New("usage: sources satl")}
		catalog,err:=sources.SATL();if err!=nil{return err}
		return enc.Encode(catalog)
	case "research":
		flags:=flag.NewFlagSet("sources research",flag.ContinueOnError)
		legacy:=flags.Bool("include-legacy",false,"explicitly include endpoints without a third-party SHA-256 lead")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if flags.NArg()!=0{return errors.New("usage: sources research [--include-legacy]")}
		ctx,cancel:=context.WithTimeout(context.Background(),7*time.Minute)
		defer cancel()
		report,researchErr:=sources.Research(ctx,*legacy)
		if err:=enc.Encode(report);err!=nil{return err}
		return researchErr
	case "endpoints":
		if len(args)!=1{return errors.New("usage: sources endpoints")}
		e,err:=sources.Endpoints();if err!=nil{return err}
		return enc.Encode(e)
	case "audit":
		flags:=flag.NewFlagSet("sources audit",flag.ContinueOnError)
		id:=flags.String("id","","observed listing ID")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if *id==""||flags.NArg()!=1{return errors.New("usage: sources audit --id ID FILE")}
		input,err:=readInput(flags.Arg(0));if err!=nil{return err}
		report,err:=sources.InspectEndpoint(*id,input,time.Now());if err!=nil{return err}
		return enc.Encode(report)
	case "fetch":
		flags:=flag.NewFlagSet("sources fetch",flag.ContinueOnError)
		id:=flags.String("id","","observed listing ID")
		path:=flags.String("out","","new local output file outside Git")
		legacy:=flags.Bool("allow-legacy-only",false,"explicitly allow unreviewed SHA-1-only research acquisition")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if *id==""||*path==""||flags.NArg()!=0{return errors.New("usage: sources fetch --id ID --out FILE [--allow-legacy-only]")}
		report,err:=sources.Fetch(context.Background(),*id,*path,*legacy);if err!=nil{return err}
		return enc.Encode(report)
	case "preview":
		flags:=flag.NewFlagSet("sources preview",flag.ContinueOnError)
		id:=flags.String("id","","research listing ID")
		fp:=flags.String("sha256","","optional independently obtained SHA-256 assertion")
		if err:=flags.Parse(args[1:]);err!=nil{return err}
		if *id==""||flags.NArg()!=1{return errors.New("usage: sources preview --id ID [--sha256 HEX] FILE")}
		input,err:=readInput(flags.Arg(0));if err!=nil{return err}
		report,err:=c.Preview(*id,input,*fp,time.Now());if err!=nil{return err}
		return enc.Encode(report)
	default:return errors.New("unknown sources command")
	}
}
