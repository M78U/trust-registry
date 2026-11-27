package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	tuf "github.com/M78U/trust-registry/tools/tuf-client"
)
func run()error{
	state:=flag.String("state","","private TUF state")
	pin:=flag.String("root-sha256","","independently pinned initial root hash")
	fp:=flag.String("fingerprint","","optional certificate fingerprint")
	flag.Parse()
	if flag.NArg()!=0||*state==""||*pin==""{return errors.New("state and root-sha256 required")}
	v,r,err:=tuf.LoadInstalled(*state,*pin);if err!=nil{return err}
	if *fp==""{return json.NewEncoder(os.Stdout).Encode(r)}
	record,err:=v.Find(*fp);if err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(struct{Report tuf.Report `json:"report"`; Certificate any `json:"certificate"`}{r,record})
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
