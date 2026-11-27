package main

import (
	"bytes"
	"testing"
)

func TestVerifyPathRequiresExplicitInputs(t *testing.T){
	for _,args:=range [][]string{{"verify-path"},{"verify-path","--purpose","document-signing","leaf.cer"},{"verify-path","--policy","p.json","--at","2026-01-01T00:00:00Z","--known-at","2026-01-01T00:00:00Z","leaf.cer"}}{
		if err:=run(args,&bytes.Buffer{});err==nil{t.Fatalf("invalid verify-path accepted: %v",args)}
	}
}
