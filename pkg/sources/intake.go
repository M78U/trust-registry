package sources

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/schemas"
)

const MaxIntakeItems = 32
const MaxIntakeBytes = 16 << 20
const MaxIntakePlanBytes = 256 << 10

type IntakeItem struct {
 ListingID string `json:"listingId"`
 FileName string `json:"fileName"`
 SourceURL string `json:"sourceURL"`
 SourceFileSHA256 string `json:"sourceFileSHA256"`
 CertificateSHA256 string `json:"certificateSHA256"`
 PublishedSHA1 string `json:"publishedSHA1"`
 PublishedSHA256Status string `json:"publishedSHA256Status"`
 PublishedSHA256 *FingerprintEvidence `json:"publishedSHA256,omitempty"`
}
type IntakePlan struct {
 SchemaVersion string `json:"schemaVersion"`
 AuthorityID string `json:"authorityId"`
 CatalogSHA256 string `json:"catalogSHA256"`
 EndpointsSHA256 string `json:"endpointsSHA256"`
 RecordedAt time.Time `json:"recordedAt"`
 AllowLegacyOnly bool `json:"allowLegacyOnly"`
 Items []IntakeItem `json:"items"`
 TrustStatus string `json:"trustStatus"`
}
type IntakeReport struct {
 PlanSHA256 string `json:"planSHA256"`
 Status string `json:"status"`
 Before registry.ValidationReport `json:"before"`
 After registry.ValidationReport `json:"after"`
 Imports []registry.ImportResult `json:"imports"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
func intakeHash(b []byte) string {
 h:=sha256.Sum256(b)
 return hex.EncodeToString(h[:])
}
func intakeTime(t time.Time) bool {
 return !t.IsZero()&&t.Location()==time.UTC&&t.Year()>=1&&t.Year()<=9999
}
func IntakePlanBytes(v IntakePlan)([]byte,error){
 raw,err:=json.Marshal(v)
 if err!=nil{return nil,err}
 raw=append(raw,'\n')
 if len(raw)>MaxIntakePlanBytes{return nil,errors.New("intake plan size limit")}
 return raw,nil
}
// DecodeIntakePlan requires a locally retained pin, not one taken from the
// plan itself. Canonical equality rejects duplicate and unknown fields.
func DecodeIntakePlan(raw []byte,pin string)(IntakePlan,error){
 var v IntakePlan
 if len(raw)==0||len(raw)>MaxIntakePlanBytes||!sha256Pattern.MatchString(pin)||intakeHash(raw)!=pin{return v,errors.New("exact intake plan pin mismatch")}
 if err:=json.Unmarshal(raw,&v);err!=nil{return v,err}
 canonical,err:=IntakePlanBytes(v)
 if err!=nil||!bytes.Equal(canonical,raw)||v.SchemaVersion!="1"||v.AuthorityID!="cn.sheca"||v.TrustStatus!="NOT_ESTABLISHED"||!intakeTime(v.RecordedAt)||!sha256Pattern.MatchString(v.CatalogSHA256)||!sha256Pattern.MatchString(v.EndpointsSHA256)||len(v.Items)<1||len(v.Items)>MaxIntakeItems{return IntakePlan{},errors.New("invalid canonical intake plan")}
 last:=""
 for _,row:=range v.Items{
  if !idPattern.MatchString(row.ListingID)||row.ListingID<=last||row.FileName!=row.ListingID+".cer"||!sha256Pattern.MatchString(row.SourceFileSHA256)||!sha256Pattern.MatchString(row.CertificateSHA256)||!sha1Pattern.MatchString(row.PublishedSHA1){return IntakePlan{},errors.New("invalid or duplicate intake item")}
  last=row.ListingID
 }
 return v,nil
}
func readIntakeFile(path string)([]byte,error){
 st,err:=os.Lstat(path);if err!=nil{return nil,err}
 if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>registry.MaxCertificateInput{return nil,errors.New("invalid candidate file type or size")}
 f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
 opened,err:=f.Stat();if err!=nil{return nil,err}
 if !opened.Mode().IsRegular()||!os.SameFile(st,opened){return nil,errors.New("candidate file changed while opening")}
 raw,err:=io.ReadAll(io.LimitReader(f,registry.MaxCertificateInput+1));if err!=nil{return nil,err}
 if len(raw)==0||len(raw)>registry.MaxCertificateInput{return nil,errors.New("candidate file size limit")}
 return raw,nil
}
type preparedIntake struct {
 plan IntakePlan
 inputs [][]byte
}
// Only explicitly selected embedded endpoints are read. No directory scan,
// network request, arbitrary source path or source URL supplied by input.
func prepareIntake(c Catalog,endpoints []Endpoint,dir string,ids []string,at time.Time,legacy bool)(preparedIntake,error){
 if !intakeTime(at)||strings.TrimSpace(dir)==""||len(ids)<1||len(ids)>MaxIntakeItems{return preparedIntake{},errors.New("explicit intake directory, listing IDs and UTC observation time required")}
 if err:=c.Validate();err!=nil{return preparedIntake{},err}
 st,err:=os.Lstat(dir);if err!=nil{return preparedIntake{},err}
 if !st.IsDir(){return preparedIntake{},errors.New("expected local candidate directory")}
 cb,err:=json.Marshal(c);if err!=nil{return preparedIntake{},err}
 eb,err:=json.Marshal(endpoints);if err!=nil{return preparedIntake{},err}
 result:=preparedIntake{plan:IntakePlan{SchemaVersion:"1",AuthorityID:c.AuthorityID,CatalogSHA256:intakeHash(cb),EndpointsSHA256:intakeHash(eb),RecordedAt:at,AllowLegacyOnly:legacy,Items:[]IntakeItem{},TrustStatus:"NOT_ESTABLISHED"}}
 byID:=map[string]Endpoint{}
 for _,e:=range endpoints{
  if _,ok:=byID[e.ListingID];ok{return preparedIntake{},errors.New("duplicate source endpoint")}
  byID[e.ListingID]=e
 }
 selected:=append([]string{},ids...)
 sort.Strings(selected)
 total:=0
 seenCert:=map[string]bool{}
 last:=""
 for _,id:=range selected{
  e,ok:=byID[id]
  if !ok||!idPattern.MatchString(id)||id==last{return preparedIntake{},errors.New("unknown or duplicate selected endpoint")}
  last=id
  if e.PublishedSHA256==nil&&!legacy{return preparedIntake{},fmt.Errorf("%s has no published SHA-256 lead; explicit legacy-only opt-in required",id)}
  name:=id+".cer"
  raw,err:=readIntakeFile(filepath.Join(dir,name));if err!=nil{return preparedIntake{},fmt.Errorf("%s: %w",id,err)}
  if len(raw)>MaxIntakeBytes-total{return preparedIntake{},errors.New("batch certificate byte budget exceeded")}
  total+=len(raw)
  report,err:=inspectEndpoint(c,e,raw,at);if err!=nil{return preparedIntake{},fmt.Errorf("%s: %w",id,err)}
  cert,prov,_,err:=registry.ImportCandidate(raw,e.DownloadURL,at);if err!=nil{return preparedIntake{},err}
  if seenCert[cert.FingerprintSHA256]{return preparedIntake{},errors.New("duplicate certificate across selected listing IDs")}
  seenCert[cert.FingerprintSHA256]=true
  if err:=schemas.ValidateValue(schemas.Certificate,cert);err!=nil{return preparedIntake{},err}
  if err:=schemas.ValidateValue(schemas.Provenance,prov);err!=nil{return preparedIntake{},err}
  result.plan.Items=append(result.plan.Items,IntakeItem{ListingID:id,FileName:name,SourceURL:e.DownloadURL,SourceFileSHA256:prov.SourceFileSHA256,CertificateSHA256:cert.FingerprintSHA256,PublishedSHA1:report.Preview.ComputedSHA1,PublishedSHA256Status:report.PublishedSHA256Status,PublishedSHA256:e.PublishedSHA256})
  result.inputs=append(result.inputs,raw)
 }
 if _,err:=IntakePlanBytes(result.plan);err!=nil{return preparedIntake{},err}
 return result,nil
}
// PlanIntake builds a deterministic offline plan from exact local copies.
// RecordedAt is an asserted observation time, not authenticated receipt.
func PlanIntake(dir string,ids []string,at time.Time,legacy bool)(IntakePlan,error){
 c,err:=SHECA();if err!=nil{return IntakePlan{},err}
 endpoints,err:=Endpoints();if err!=nil{return IntakePlan{},err}
 v,err:=prepareIntake(c,endpoints,dir,ids,at,legacy)
 if err!=nil{return IntakePlan{},err}
 return v.plan,nil
}
func applyIntake(s *registry.Store,c Catalog,endpoints []Endpoint,dir string,raw []byte,pin string)(IntakeReport,error){
 if s==nil{return IntakeReport{},errors.New("initialized candidate store required")}
 plan,err:=DecodeIntakePlan(raw,pin);if err!=nil{return IntakeReport{},err}
 ids:=make([]string,0,len(plan.Items))
 for _,row:=range plan.Items{ids=append(ids,row.ListingID)}
 prepared,err:=prepareIntake(c,endpoints,dir,ids,plan.RecordedAt,plan.AllowLegacyOnly);if err!=nil{return IntakeReport{},err}
 canonical,err:=IntakePlanBytes(prepared.plan);if err!=nil{return IntakeReport{},err}
 if !bytes.Equal(canonical,raw){return IntakeReport{},errors.New("intake inputs or embedded source catalog changed")}
 // All inputs, schema checks and destination validation precede writes.
 // Store is an operator-controlled single-writer inventory, not a transaction.
 before,err:=s.Validate();if err!=nil{return IntakeReport{},err}
 report:=IntakeReport{PlanSHA256:pin,Status:"INCOMPLETE_LOCAL_IMPORT",Before:before,Imports:[]registry.ImportResult{},TrustStatus:"NOT_ESTABLISHED"}
 for i,row:=range prepared.plan.Items{
  imported,err:=s.Import(prepared.inputs[i],row.SourceURL,plan.RecordedAt)
  if err!=nil{return report,fmt.Errorf("candidate %s: %w",row.ListingID,err)}
  report.Imports=append(report.Imports,imported)
 }
 after,err:=s.Validate();if err!=nil{return report,err}
 report.After=after
 report.Status="UNREVIEWED_BATCH_IMPORTED"
 return report,nil
}
// ApplyIntake imports unreviewed candidates only. A byte-identical retry
// reuses the original plan time/source/raw hash and existing immutable files.
func ApplyIntake(s *registry.Store,dir string,raw []byte,pin string)(IntakeReport,error){
 c,err:=SHECA();if err!=nil{return IntakeReport{},err}
 endpoints,err:=Endpoints();if err!=nil{return IntakeReport{},err}
 return applyIntake(s,c,endpoints,dir,raw,pin)
}
