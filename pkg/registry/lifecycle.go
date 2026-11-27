package registry

import (
 "errors"
 "sort"
 "time"
)

const MaxLifecycleRecords = 8192
const MaxWarningDays = 365

const (
 ValidityNotYetValid = "NOT_YET_VALID"
 ValidityCurrent = "WITHIN_VALIDITY"
 ValidityExpiring = "EXPIRING_SOON"
 ValidityExpired = "EXPIRED"
 ValidityInvalidInterval = "INVALID_VALIDITY_INTERVAL"
)

type LifecycleOptions struct {
 At time.Time
 WarningDays int
}
type LifecycleEntry struct {
 Certificate CertificateRecord `json:"certificate"`
 ValidityStatus string `json:"validityStatus"`
 RevocationStatus string `json:"revocationStatus"`
 TrustStatus string `json:"trustStatus"`
}
type LifecycleReport struct {
 EvaluationTime time.Time `json:"evaluationTime"`
 WarningDays int `json:"warningDays"`
 InventoryScope string `json:"inventoryScope"`
 Counts map[string]int `json:"counts"`
 Certificates []LifecycleEntry `json:"certificates"`
 RevocationStatus string `json:"revocationStatus"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
func validateLifecycleOptions(o LifecycleOptions)error{
 if o.At.IsZero()||o.At.Location()!=time.UTC||o.At.Year()<1||o.At.Year()>9999||o.WarningDays<0||o.WarningDays>MaxWarningDays{return errors.New("explicit UTC time and warning days in 0..365 required")}
 if o.At.AddDate(0,0,o.WarningDays).Year()>9999{return errors.New("warning horizon outside supported range")}
 return nil
}
func classifyValidity(c CertificateRecord,o LifecycleOptions)string{
 switch {
 case c.NotBefore.IsZero()||c.NotAfter.IsZero()||c.NotAfter.Before(c.NotBefore):return ValidityInvalidInterval
 case o.At.Before(c.NotBefore):return ValidityNotYetValid
 case o.At.After(c.NotAfter):return ValidityExpired
 case !c.NotAfter.After(o.At.AddDate(0,0,o.WarningDays)):return ValidityExpiring
 default:return ValidityCurrent
 }
}

// Lifecycle evaluates validity dates parsed from DER in the validated current
// inventory. It does not reconstruct historical inventory membership, inspect
// revocation, authenticate sources or infer scoped authorization.
func(i *Index)Lifecycle(o LifecycleOptions)(LifecycleReport,error){
 if err:=validateLifecycleOptions(o);err!=nil{return LifecycleReport{},err}
 if _,err:=i.Report();err!=nil{return LifecycleReport{},err}
 if len(i.all)>MaxLifecycleRecords{return LifecycleReport{},errors.New("lifecycle report record limit exceeded")}
 report:=LifecycleReport{EvaluationTime:o.At,WarningDays:o.WarningDays,InventoryScope:"CURRENT_VALIDATED_INVENTORY",Counts:map[string]int{ValidityNotYetValid:0,ValidityCurrent:0,ValidityExpiring:0,ValidityExpired:0,ValidityInvalidInterval:0},Certificates:[]LifecycleEntry{},RevocationStatus:"NOT_CHECKED",TrustStatus:"NOT_ESTABLISHED"}
 for _,fp:=range i.all{
  c:=i.records[fp];status:=classifyValidity(c,o)
  report.Counts[status]++
  report.Certificates=append(report.Certificates,LifecycleEntry{c,status,"NOT_CHECKED","NOT_ESTABLISHED"})
 }
 // Chronological expiry first, then fingerprint, for stable monitoring output.
 sort.Slice(report.Certificates,func(a,b int)bool{
  x,y:=report.Certificates[a].Certificate,report.Certificates[b].Certificate
  if !x.NotAfter.Equal(y.NotAfter){return x.NotAfter.Before(y.NotAfter)}
  return x.FingerprintSHA256<y.FingerprintSHA256
 })
 return report,nil
}

func(s *Store)Lifecycle(o LifecycleOptions)(LifecycleReport,error){
 if err:=validateLifecycleOptions(o);err!=nil{return LifecycleReport{},err}
 i,err:=s.BuildIndex();if err!=nil{return LifecycleReport{},err}
 return i.Lifecycle(o)
}
