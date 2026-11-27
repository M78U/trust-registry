package registry

import (
 "errors"
 "path/filepath"
)

// ReadCertificateDER returns owned, content-checked CA inventory bytes.
// It never exports an ephemeral end-entity input.
func(s *Store)ReadCertificateDER(fp string)([]byte,error){
 if s==nil{return nil,errors.New("registry store required")}
 r,err:=s.Find(fp);if err!=nil{return nil,err}
 raw,err:=readRegular(filepath.Join(s.root,"certificates",fp+".der"),MaxCertificateInput);if err!=nil{return nil,err}
 if digest(raw)!=r.FingerprintSHA256{return nil,errors.New("certificate changed during read")}
 return raw,nil
}
