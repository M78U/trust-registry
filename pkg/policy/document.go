package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const MaxDocumentBytes = 4 << 20

// LoadDocument accepts one bounded JSON document. Require exactly the known
// fields and reject duplicate object keys before decoding.
func LoadDocument(path string) (Document,error) {
	var d Document
	info,err:=os.Lstat(path)
	if err!=nil { return d,err }
	if !info.Mode().IsRegular() || info.Size()>MaxDocumentBytes { return d,errors.New("invalid policy document type or size") }
	f,err:=os.Open(path)
	if err!=nil { return d,err }
	defer f.Close()
	opened,err:=f.Stat()
	if err!=nil { return d,err }
	if !opened.Mode().IsRegular() || !os.SameFile(info,opened) { return d,errors.New("policy file changed while opening") }
	b,err:=io.ReadAll(io.LimitReader(f,MaxDocumentBytes+1))
	if err!=nil { return d,err }
	if len(b)>MaxDocumentBytes { return d,errors.New("policy document too large") }
	return DecodeDocument(b)
}

func DecodeDocument(b []byte) (Document,error) {
	var d Document
	if len(b)>MaxDocumentBytes { return d,errors.New("policy document too large") }
	tokens:=json.NewDecoder(bytes.NewReader(b))
	if err:=checkValue(tokens,0);err!=nil { return d,err }
	if _,err:=tokens.Token();err!=io.EOF { return d,errors.New("trailing policy content") }
	dec:=json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err:=dec.Decode(&d);err!=nil { return d,err }
	// Require canonical spelling and complete fields, independent of whitespace
	// or member order. This also rejects omitted zero-valued constraints.
	var original any
	if err:=json.Unmarshal(b,&original);err!=nil { return d,err }
	encoded,err:=json.Marshal(d)
	if err!=nil { return d,err }
	var expected any
	if err:=json.Unmarshal(encoded,&expected);err!=nil { return d,err }
	if !sameJSONShape(original,expected) { return d,errors.New("missing or incorrectly spelled policy fields") }
	return d,nil
}

func sameJSONShape(a,b any) bool {
	switch v:=a.(type) {
	case map[string]any:
		w,ok:=b.(map[string]any);if !ok || len(v)!=len(w) { return false }
		for k,x:=range v { y,ok:=w[k];if !ok || !sameJSONShape(x,y) { return false } };return true
	case []any:
		w,ok:=b.([]any);if !ok || len(v)!=len(w) { return false }
		for i,x:=range v { if !sameJSONShape(x,w[i]) { return false } };return true
	case nil: return b==nil
	case bool: _,ok:=b.(bool);return ok
	case string: _,ok:=b.(string);return ok
	case float64: _,ok:=b.(float64);return ok
	default:return false
	}
}

func checkValue(d *json.Decoder,depth int) error {
	if depth>32 { return errors.New("policy JSON nesting limit exceeded") }
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
