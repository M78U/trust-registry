package snapshot

import (
 "errors"
 "time"

 "github.com/M78U/trust-registry/pkg/revocation"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/validation"
)

// VerifyLocalPathWithRevocation uses exact installed policy and separate
// private evidence observations. Evidence is not part of the public snapshot.
func(v *Loaded)VerifyLocalPathWithRevocation(input []byte,id string,version int,purpose,dnsName string,at,knownAt time.Time,evidence *revocation.EvidenceStore)(validation.LocalPathWithRevocationReport,error){
 d,err:=v.Policy(id,version);if err!=nil{return validation.LocalPathWithRevocationReport{},err}
 if knownAt.After(v.loadedAt){return validation.LocalPathWithRevocationReport{},errors.New("knowledge time exceeds snapshot load time")}
 var result validation.LocalPathWithRevocationReport
 err=v.withStore(func(s *registry.Store)error{
  var err error
  result,err=validation.VerifyLocalPathWithRevocation(s,d,input,purpose,dnsName,at,knownAt,evidence)
  return err
 })
 if err!=nil{return validation.LocalPathWithRevocationReport{},err}
 return result,nil
}
