package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/M78U/trust-registry/schemas"
)

const MaxDocumentBytes = schemas.MaxJSONBytes

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
	if err:=schemas.ValidateJSON(schemas.PolicyDocument,b);err!=nil { return d,err }
	dec:=json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err:=dec.Decode(&d);err!=nil { return d,err }
	return d,nil
}
