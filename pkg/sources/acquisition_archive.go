package sources

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net/http"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/schemas"
)

const MaxAcquisitionArchiveBytes = 2 << 20

// AcquisitionArchive is a local observation, not a signed network receipt.
// Raw contains exact original downloaded bytes, not normalized DER.
type AcquisitionArchive struct {
 SchemaVersion string `json:"schemaVersion"`
 ListingID string `json:"listingId"`
 CatalogSHA256 string `json:"catalogSHA256"`
 EndpointsSHA256 string `json:"endpointsSHA256"`
 RecordedAt time.Time `json:"recordedAt"`
 LegacyOnlyAllowed bool `json:"legacyOnlyAllowed"`
 Report AcquisitionReport `json:"report"`
 Raw []byte `json:"raw"`
}
type ArchiveReceipt struct {
 ListingID string `json:"listingId"`
 ArchiveSHA256 string `json:"archiveSHA256"`
 SourceFileSHA256 string `json:"sourceFileSHA256"`
 CertificateSHA256 string `json:"certificateSHA256"`
 RecordedAt time.Time `json:"recordedAt"`
 Status string `json:"status"`
 FetchOperations int `json:"fetchOperations"`
 PinMatched bool `json:"pinMatched"`
 ObservationAuthentication string `json:"observationAuthentication"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
type ArchiveImportReport struct {
 Receipt ArchiveReceipt `json:"receipt"`
 Import registry.ImportResult `json:"import"`
 Status string `json:"status"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
func archiveBytes(a AcquisitionArchive)([]byte,error){
 b,err:=json.Marshal(a);if err!=nil{return nil,err}
 b=append(b,'\n')
 if len(b)>MaxAcquisitionArchiveBytes{return nil,errors.New("acquisition archive size limit")}
 return b,nil
}
func archiveEndpoint(endpoints []Endpoint,id string)(Endpoint,error){
 if !idPattern.MatchString(id){return Endpoint{},errors.New("invalid listing ID")}
 var match Endpoint;count:=0
 for _,v:=range endpoints{if v.ListingID==id{match=v;count++}}
 if count!=1{return Endpoint{},errors.New("explicit observed endpoint required")}
 return match,nil
}
func buildArchive(c Catalog,endpoints []Endpoint,id string,raw []byte,at time.Time,legacy bool)(AcquisitionArchive,error){
 if !intakeTime(at)||len(raw)==0||len(raw)>registry.MaxCertificateInput{return AcquisitionArchive{},errors.New("invalid original certificate bytes or UTC time")}
 e,err:=archiveEndpoint(endpoints,id);if err!=nil{return AcquisitionArchive{},err}
 if e.PublishedSHA256==nil&&!legacy{return AcquisitionArchive{},errors.New("legacy-only observation requires explicit opt-in")}
 report,err:=inspectEndpoint(c,e,raw,at);if err!=nil{return AcquisitionArchive{},err}
 cert,prov,_,err:=registry.ImportCandidate(raw,e.DownloadURL,at);if err!=nil{return AcquisitionArchive{},err}
 if err:=schemas.ValidateValue(schemas.Certificate,cert);err!=nil{return AcquisitionArchive{},err}
 if err:=schemas.ValidateValue(schemas.Provenance,prov);err!=nil{return AcquisitionArchive{},err}
 report.Preview.Provenance=prov
 // Stored assertion only. Reconstructing it offline does not prove HTTP
 // retrieval or receipt time; both remain unauthenticated observations.
 report.AcquisitionStatus="ARCHIVED_DOWNLOAD_OBSERVATION"
 report.OriginalFileSaved=true
 cb,err:=json.Marshal(c);if err!=nil{return AcquisitionArchive{},err}
 eb,err:=json.Marshal(endpoints);if err!=nil{return AcquisitionArchive{},err}
 return AcquisitionArchive{SchemaVersion:"1",ListingID:id,CatalogSHA256:intakeHash(cb),EndpointsSHA256:intakeHash(eb),RecordedAt:at,LegacyOnlyAllowed:legacy,Report:report,Raw:bytes.Clone(raw)},nil
}
func archiveDir(dir string)error{
 if strings.TrimSpace(dir)==""{return errors.New("explicit existing private archive directory required")}
 st,err:=os.Lstat(dir);if err!=nil{return err}
 if !st.IsDir(){return errors.New("archive directory must be a real directory")}
 return nil
}
func decodeArchive(c Catalog,endpoints []Endpoint,id string,b []byte,pin string)(AcquisitionArchive,error){
 var a AcquisitionArchive
 if len(b)==0||len(b)>MaxAcquisitionArchiveBytes||pin!=""&&(!sha256Pattern.MatchString(pin)||intakeHash(b)!=pin){return a,errors.New("acquisition archive size or pin mismatch")}
 if err:=json.Unmarshal(b,&a);err!=nil{return a,err}
 if a.ListingID!=id||a.SchemaVersion!="1"{return AcquisitionArchive{},errors.New("archive identity mismatch")}
 fresh,err:=buildArchive(c,endpoints,id,a.Raw,a.RecordedAt,a.LegacyOnlyAllowed);if err!=nil{return AcquisitionArchive{},err}
 canonical,err:=archiveBytes(fresh)
 if err!=nil||!bytes.Equal(canonical,b){return AcquisitionArchive{},errors.New("archive bytes, metadata or current source catalog mismatch")}
 return fresh,nil
}
func makeArchiveReceipt(a AcquisitionArchive,b []byte,status string,ops int,pinned bool)ArchiveReceipt{
 return ArchiveReceipt{ListingID:a.ListingID,ArchiveSHA256:intakeHash(b),SourceFileSHA256:a.Report.Preview.Provenance.SourceFileSHA256,CertificateSHA256:a.Report.Preview.Certificate.FingerprintSHA256,RecordedAt:a.RecordedAt,Status:status,FetchOperations:ops,PinMatched:pinned,ObservationAuthentication:"NOT_ESTABLISHED",TrustStatus:"NOT_ESTABLISHED"}
}
func readArchive(c Catalog,endpoints []Endpoint,dir,id,pin string)(AcquisitionArchive,[]byte,error){
 if _,err:=archiveEndpoint(endpoints,id);err!=nil{return AcquisitionArchive{},nil,err}
 if err:=archiveDir(dir);err!=nil{return AcquisitionArchive{},nil,err}
 b,err:=readBundleArchiveFile(dir,id+".json",MaxAcquisitionArchiveBytes);if err!=nil{return AcquisitionArchive{},nil,err}
 a,err:=decodeArchive(c,endpoints,id,b,pin)
 return a,b,err
}
func commitArchive(dir,id string,b []byte)error{
 f,err:=os.CreateTemp(dir,".pending-");if err!=nil{return err}
 defer os.Remove(f.Name())
 if _,err=f.Write(b);err==nil{err=f.Sync()}
 closeErr:=f.Close();if err==nil{err=closeErr};if err!=nil{return err}
 return os.Link(f.Name(),filepath.Join(dir,id+".json"))
}
// AcquireArchived performs at most one explicit fetch operation. A valid
// existing observation is reused; corrupt or changed archives fail closed.
// The per-listing lock prevents duplicate concurrent acquisitions by
// cooperating processes. A new observation needs a different directory.
func AcquireArchived(ctx context.Context,dir,id string,legacy bool)(ArchiveReceipt,error){
 c,err:=SHECA();if err!=nil{return ArchiveReceipt{},err}
 endpoints,err:=Endpoints();if err!=nil{return ArchiveReceipt{},err}
 client,closeClient:=newResearchClient();defer closeClient()
 return acquireArchived(ctx,client,c,endpoints,dir,id,legacy)
}
func acquireArchived(ctx context.Context,client *http.Client,c Catalog,endpoints []Endpoint,dir,id string,legacy bool)(ArchiveReceipt,error){
 e,err:=archiveEndpoint(endpoints,id);if err!=nil{return ArchiveReceipt{},err}
 if e.PublishedSHA256==nil&&!legacy{return ArchiveReceipt{},errors.New("explicit legacy-only opt-in required")}
 if err:=archiveDir(dir);err!=nil{return ArchiveReceipt{},err}
 if err:=ctx.Err();err!=nil{return ArchiveReceipt{},err}
 lock:=filepath.Join(dir,id+".lock")
 if err:=os.Mkdir(lock,0700);err!=nil{return ArchiveReceipt{},fmt.Errorf("acquisition locked: %w",err)}
 defer os.Remove(lock)
 path:=filepath.Join(dir,id+".json")
 if _,err:=os.Lstat(path);err==nil{
  a,b,err:=readArchive(c,endpoints,dir,id,"");if err!=nil{return ArchiveReceipt{},err}
  return makeArchiveReceipt(a,b,"EXISTING_LOCAL_OBSERVATION_REUSED",0,false),nil
 }else if !os.IsNotExist(err){return ArchiveReceipt{},err}
 raw,report,err:=fetchBytes(ctx,client,c,e,legacy);if err!=nil{return ArchiveReceipt{},err}
 a,err:=buildArchive(c,endpoints,id,raw,report.Preview.Provenance.RecordedAt,legacy);if err!=nil{return ArchiveReceipt{},err}
 b,err:=archiveBytes(a);if err!=nil{return ArchiveReceipt{},err}
 if err:=commitArchive(dir,id,b);err!=nil{return ArchiveReceipt{},err}
 return makeArchiveReceipt(a,b,"NEW_DOWNLOAD_OBSERVATION_ARCHIVED",1,false),nil
}
// InspectArchived verifies an independently retained digest and replays all
// local source/certificate checks. It returns metadata but not raw bytes.
func InspectArchived(dir,id,pin string)(ArchiveReceipt,AcquisitionReport,error){
 c,err:=SHECA();if err!=nil{return ArchiveReceipt{},AcquisitionReport{},err}
 endpoints,err:=Endpoints();if err!=nil{return ArchiveReceipt{},AcquisitionReport{},err}
 if !sha256Pattern.MatchString(pin){return ArchiveReceipt{},AcquisitionReport{},errors.New("independent archive SHA-256 required")}
 a,b,err:=readArchive(c,endpoints,dir,id,pin);if err!=nil{return ArchiveReceipt{},AcquisitionReport{},err}
 return makeArchiveReceipt(a,b,"PINNED_LOCAL_OBSERVATION_VERIFIED",0,true),a.Report,nil
}
// ArchivedOriginal returns an exact copy for private human review.
func ArchivedOriginal(dir,id,pin string)([]byte,error){
 if !sha256Pattern.MatchString(pin){return nil,errors.New("independent archive SHA-256 required")}
 c,err:=SHECA();if err!=nil{return nil,err}
 endpoints,err:=Endpoints();if err!=nil{return nil,err}
 a,_,err:=readArchive(c,endpoints,dir,id,pin);if err!=nil{return nil,err}
 return a.Raw,nil
}
func ImportArchived(s *registry.Store,dir,id,pin string)(ArchiveImportReport,error){
 c,err:=SHECA();if err!=nil{return ArchiveImportReport{},err}
 endpoints,err:=Endpoints();if err!=nil{return ArchiveImportReport{},err}
 return importArchived(s,c,endpoints,dir,id,pin)
}
func importArchived(s *registry.Store,c Catalog,endpoints []Endpoint,dir,id,pin string)(ArchiveImportReport,error){
 if s==nil||!sha256Pattern.MatchString(pin){return ArchiveImportReport{},errors.New("initialized inventory and independent archive pin required")}
 a,b,err:=readArchive(c,endpoints,dir,id,pin);if err!=nil{return ArchiveImportReport{},err}
 if _,err:=s.Validate();err!=nil{return ArchiveImportReport{},err}
 result,err:=s.Import(a.Raw,a.Report.Endpoint.DownloadURL,a.RecordedAt);if err!=nil{return ArchiveImportReport{},err}
 r:=ArchiveImportReport{Receipt:makeArchiveReceipt(a,b,"PINNED_LOCAL_OBSERVATION_VERIFIED",0,true),Import:result,Status:"LOCAL_IMPORT_WRITTEN_VALIDATION_PENDING",TrustStatus:"NOT_ESTABLISHED"}
 if _,err:=s.Validate();err!=nil{return r,err}
 r.Status="UNREVIEWED_ARCHIVED_CANDIDATE_IMPORTED"
 return r,nil
}
