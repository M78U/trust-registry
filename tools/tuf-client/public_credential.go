package tufclient

import (
 "bytes"
 "encoding/json"
 "errors"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
 "github.com/theupdateframework/go-tuf/v2/metadata"
)

type publicTargetCustom struct {
 ReleaseCredential []byte `json:"releaseCredential"`
}
func encodeCredentialCustom(raw []byte)(*json.RawMessage,error){
 if _,err:=review.DecodeCredential(raw);err!=nil{return nil,err}
 b,err:=json.Marshal(publicTargetCustom{raw});if err!=nil{return nil,err}
 v:=json.RawMessage(b);return &v,nil
}
func decodeCredentialCustom(custom *json.RawMessage)(review.PublicCredential,error){
 if custom==nil||len(*custom)>2*review.MaxCredentialBytes{return review.PublicCredential{},errors.New("required public release credential missing or oversized")}
 var v publicTargetCustom
 if err:=json.Unmarshal(*custom,&v);err!=nil{return review.PublicCredential{},err}
 canonical,err:=json.Marshal(v);if err!=nil{return review.PublicCredential{},err}
 var compact bytes.Buffer
 if err:=json.Compact(&compact,*custom);err!=nil||!bytes.Equal(canonical,compact.Bytes()){return review.PublicCredential{},errors.New("noncanonical credential custom field")}
 return review.DecodeCredential(v.ReleaseCredential)
}
// LoadReviewAuthority reads the independently provisioned configuration.
// It is never downloaded from the repository or accepted from target data.
func LoadReviewAuthority(path,pin string)(*review.Authority,error){
 raw,err:=readRegular(path,review.MaxAuthorityBytes);if err!=nil{return nil,err}
 return review.ParseAuthority(raw,pin)
}
func checkPublicCredential(a *review.Authority,chain [][]byte,pin string,info *metadata.TargetFiles,seq int64,targetsExpiry,snapshotExpiry,timestampExpiry,at time.Time)(review.CredentialReport,error){
 if a==nil||len(chain)==0||info==nil||seq<1||len(info.Hashes["sha256"])!=32{return review.CredentialReport{},errors.New("invalid public release context")}
 for _,raw:=range chain{
  root,err:=metadata.Root().FromBytes(raw);if err!=nil{return review.CredentialReport{},err}
  if err:=strictRootProfile(root,a);err!=nil{return review.CredentialReport{},err}
 }
 c,err:=decodeCredentialCustom(info.Custom);if err!=nil{return review.CredentialReport{},err}
 b:=review.ReleaseBinding{InitialRootSHA256:pin,CurrentRootSHA256:digest(chain[len(chain)-1]),SnapshotSHA256:fmtHash(info.Hashes["sha256"]),Sequence:uint64(seq),TargetsExpires:targetsExpiry.UTC(),SnapshotMetadataExpires:snapshotExpiry.UTC(),TimestampExpires:timestampExpiry.UTC()}
 return review.VerifyCredential(a,c,b,at)
}
func fmtHash(b []byte)string{
 const alphabet="0123456789abcdef"
 s:=make([]byte,2*len(b));for i,v:=range b{s[2*i]=alphabet[v>>4];s[2*i+1]=alphabet[v&15]};return string(s)
}
