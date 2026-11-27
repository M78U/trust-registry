package registry

import (
 "errors"

 "github.com/emmansun/gmsm/smx509"
)

// MatchIssuer checks a caller-supplied candidate with the same direct issuer
// rules as local discovery. No inventory writes, path validation or trust.
func MatchIssuer(input,candidate []byte)(IssuerCandidate,error){
 childRecord,childDER,err:=ParseCertificate(input);if err!=nil{return IssuerCandidate{},err}
 parentRecord,parentDER,err:=ParseCertificate(candidate);if err!=nil{return IssuerCandidate{},err}
 if childRecord.FingerprintSHA256==parentRecord.FingerprintSHA256{return IssuerCandidate{},errors.New("certificate cannot be its own candidate")}
 child,err:=smx509.ParseCertificate(childDER);if err!=nil{return IssuerCandidate{},err}
 parent,err:=smx509.ParseCertificate(parentDER);if err!=nil{return IssuerCandidate{},err}
 row,ok:=checkDirectIssuer(child,parent,parentRecord)
 if !ok{return IssuerCandidate{},errors.New("no direct issuer identity match")}
 return row,nil
}
