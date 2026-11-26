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
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	info, err := f.Stat()
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() { return nil, errors.New("expected regular file") }
	data, err := io.ReadAll(io.LimitReader(f, registry.MaxCertificateInput+1))
	if err != nil { return nil, err }
	if len(data) > registry.MaxCertificateInput { return nil, errors.New("certificate input too large") }
	return data, nil
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 { return errors.New("usage: trust-registry inspect FILE | import --source HTTPS_URL FILE") }
	switch args[0] {
	case "inspect":
		if len(args) != 2 { return errors.New("usage: inspect FILE") }
		input, err := readInput(args[1])
		if err != nil { return err }
		record, _, err := registry.ParseCertificate(input)
		if err != nil { return err }
		return json.NewEncoder(out).Encode(record)
	case "import":
		flags := flag.NewFlagSet("import", flag.ContinueOnError)
		source := flags.String("source", "", "asserted public source URL (not fetched)")
		if err := flags.Parse(args[1:]); err != nil { return err }
		if flags.NArg() != 1 { return errors.New("usage: import --source HTTPS_URL FILE") }
		input, err := readInput(flags.Arg(0))
		if err != nil { return err }
		record, provenance, _, err := registry.ImportCandidate(input, *source, time.Now())
		if err != nil { return err }
		return json.NewEncoder(out).Encode(struct {
			Certificate registry.CertificateRecord `json:"certificate"`
			Provenance registry.ProvenanceRecord `json:"provenance"`
		}{record, provenance})
	default:
		return errors.New("unknown command")
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
