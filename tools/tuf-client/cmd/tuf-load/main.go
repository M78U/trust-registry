package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	tuf "github.com/M78U/trust-registry/tools/tuf-client"
	"github.com/M78U/trust-registry/pkg/snapshot"
)
func run()error{
	state:=flag.String("state","","private TUF state")
	pin:=flag.String("root-sha256","","independently pinned initial root hash")
	fp:=flag.String("fingerprint","","optional certificate fingerprint")
	authority:=flag.String("authority","","independently provisioned review authority file")
	authorityPin:=flag.String("authority-sha256","","independent authority pin")
	flag.Parse()
	if flag.NArg()!=0||*state==""||*pin==""{return errors.New("state and root-sha256 required")}
	if (*authority=="")!=(*authorityPin==""){return errors.New("authority and authority-sha256 must be supplied together")}
	var v *snapshot.Loaded;var r tuf.Report;var err error
	if *authority!=""{a,e:=tuf.LoadReviewAuthority(*authority,*authorityPin);if e!=nil{return e};v,r,err=tuf.LoadAuthorizedInstalled(*state,*pin,a)}else{v,r,err=tuf.LoadInstalled(*state,*pin)}
	if err!=nil{return err}
	if *fp==""{return json.NewEncoder(os.Stdout).Encode(r)}
	record,err:=v.Find(*fp);if err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(struct{Report tuf.Report `json:"report"`; Certificate any `json:"certificate"`}{r,record})
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
