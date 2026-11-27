package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestEmptyRegistrySmoke(t *testing.T) {
	root:=filepath.Join(t.TempDir(),"inventory")
	var out bytes.Buffer
	for _,args:=range [][]string{
		{"init","--registry",root},
		{"init","--registry",root},
		{"validate","--registry",root},
		{"search","--registry",root},
		{"policy","list"},
		{"validate","--registry",root,"--policy",filepath.Join("..","..","testdata","policies","empty-cn-document-signing.json")},
	} {
		out.Reset()
		if err:=run(args,&out);err!=nil { t.Fatalf("%v: %v",args,err) }
		if !json.Valid(out.Bytes()) { t.Fatalf("invalid JSON: %s",out.String()) }
	}
}
