package snapshot

import (
 "errors"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
)

func(v *Loaded)Lifecycle(o registry.LifecycleOptions)(registry.LifecycleReport,error){
 if v==nil||v.index==nil{return registry.LifecycleReport{},errors.New("loaded snapshot required")}
 // Forecasting uses WarningDays, not a fictitious future evaluation time.
 if o.At.After(v.loadedAt){return registry.LifecycleReport{},errors.New("evaluation exceeds snapshot load time")}
 return v.index.Lifecycle(o)
}

func(v *Loaded)PolicyHistory(id string,version int,fp string,at,knownAt time.Time)(policy.HistoryReport,error){
 d,err:=v.Policy(id,version);if err!=nil{return policy.HistoryReport{},err}
 if knownAt.After(v.loadedAt){return policy.HistoryReport{},errors.New("knowledge time exceeds snapshot load time")}
 var result policy.HistoryReport
 err=v.withStore(func(s *registry.Store)error{
  var err error
  result,err=d.History(s,fp,at,knownAt)
  return err
 })
 if err!=nil{return policy.HistoryReport{},err}
 return result,nil
}
