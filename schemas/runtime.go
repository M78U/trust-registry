// Package schemas validates registry JSON against the embedded, versioned
// Draft 2020-12 schemas. It never resolves external files or network URLs.
package schemas

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed *.schema.json
var files embed.FS

const MaxJSONBytes = 4 << 20
const baseURL = "https://schemas.m78u.invalid/trust-registry/v1/"

const (
	Certificate = "certificate.schema.json"
	Provenance = "provenance.schema.json"
	Policy = "policy.schema.json"
	ProvenanceReview = "provenance-review.schema.json"
	Decision = "decision.schema.json"
	PolicyDocument = "policy-document.schema.json"
	ReleaseReview = "release-review.schema.json"
	ReviewAuthority = "review-authority.schema.json"
)

var loadOnce sync.Once
var compiled map[string]*jsonschema.Schema
var compileErr error

type denyLoader struct{}
func (denyLoader) Load(string) (any,error) {
	return nil,errors.New("external schema references are disabled")
}

func compileAll() {
	c:=jsonschema.NewCompiler()
	c.AssertFormat()
	c.UseLoader(denyLoader{})
	names:=[]string{Certificate,Provenance,Policy,ProvenanceReview,Decision,PolicyDocument,ReleaseReview,ReviewAuthority}
	for _,name:=range names {
		b,err:=files.ReadFile(name)
		if err!=nil { compileErr=err;return }
		doc,err:=jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err!=nil { compileErr=err;return }
		if err=c.AddResource(baseURL+name,doc);err!=nil { compileErr=err;return }
	}
	result:=make(map[string]*jsonschema.Schema,len(names))
	for _,name:=range names {
		s,err:=c.Compile(baseURL+name)
		if err!=nil { compileErr=fmt.Errorf("compile %s: %w",name,err);return }
		result[name]=s
	}
	compiled=result
}

// ValidateJSON accepts one bounded UTF-8 JSON value, rejects duplicate keys
// and excessive nesting before applying the selected embedded schema.
func ValidateJSON(name string,b []byte) error {
	if len(b)==0 || len(b)>MaxJSONBytes || !utf8.Valid(b) { return errors.New("invalid JSON size or encoding") }
	loadOnce.Do(compileAll)
	if compileErr!=nil { return compileErr }
	s,ok:=compiled[name]
	if !ok { return errors.New("unknown embedded schema") }
	tokens:=json.NewDecoder(bytes.NewReader(b))
	tokens.UseNumber()
	if err:=checkValue(tokens,0);err!=nil { return err }
	if _,err:=tokens.Token();err!=io.EOF { return errors.New("trailing JSON content") }
	doc,err:=jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err!=nil { return err }
	if err:=s.Validate(doc);err!=nil { return fmt.Errorf("%s: %w",name,err) }
	return nil
}

func ValidateValue(name string,v any) error {
	b,err:=json.Marshal(v)
	if err!=nil { return err }
	return ValidateJSON(name,b)
}

func checkValue(d *json.Decoder,depth int) error {
	if depth>32 { return errors.New("JSON nesting limit exceeded") }
	t,err:=d.Token()
	if err!=nil { return err }
	switch t {
	case json.Delim('{'):
		seen:=map[string]bool{}
		for d.More() {
			k,err:=d.Token();if err!=nil { return err }
			key,ok:=k.(string);if !ok || seen[key] { return errors.New("invalid or duplicate JSON object key") };seen[key]=true
			if err:=checkValue(d,depth+1);err!=nil { return err }
		}
		end,err:=d.Token();if err!=nil || end!=json.Delim('}') { return errors.New("invalid JSON object") }
	case json.Delim('['):
		for d.More() { if err:=checkValue(d,depth+1);err!=nil { return err } }
		end,err:=d.Token();if err!=nil || end!=json.Delim(']') { return errors.New("invalid JSON array") }
	case json.Delim('}'),json.Delim(']'):return errors.New("unexpected JSON delimiter")
	}
	return nil
}
