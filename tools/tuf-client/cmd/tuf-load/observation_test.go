package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	tuf "github.com/M78U/trust-registry/tools/tuf-client"
)

func TestOnlineObservationJSON(t *testing.T){
	x:=tuf.RefreshObservation{InitialRootSHA256:strings.Repeat("a",64),AuthoritySHA256:strings.Repeat("b",64),Checkpoint:tuf.ReleaseCheckpoint{Sequence:1,SnapshotSHA256:strings.Repeat("c",64),RootVersion:1},CompletedAt:time.Date(2026,11,27,12,0,0,0,time.UTC)}
	raw,err:=json.Marshal(x);if err!=nil{t.Fatal(err)}
	got,err:=parseOnlineObservation(string(raw));if err!=nil||got!=x{t.Fatal(got,err)}
	for _,bad:=range []string{"","{}", "null",string(raw)+" ",string(raw[:len(raw)-1])+ `,"extra":true}`,string(raw[:len(raw)-1])+`,"initialRootSHA256":"other"}`,strings.Repeat("x",4097)}{
		if _,err:=parseOnlineObservation(bad);err==nil{t.Fatal("accepted invalid observation JSON")}
	}
}
