package sources

import (
 "context"
 "errors"
 "fmt"
 "net/http"
 "sort"

 "github.com/M78U/trust-registry/pkg/registry"
)

// MaxArchiveBatch limits one explicit operator operation. The initial v0.2
// SHECA batch contains three independently published SHA-256 leads.
const MaxArchiveBatch=8

type ArchiveBatchFetchReport struct{
 Status string `json:"status"`
 RequestedIDs []string `json:"requestedIds"`
 Receipts []ArchiveReceipt `json:"receipts"`
 FailedListingID string `json:"failedListingId,omitempty"`
 SuccessfulFetchOperations int `json:"successfulFetchOperations"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}

type ArchiveBatchImportReport struct{
 Status string `json:"status"`
 RequestedIDs []string `json:"requestedIds"`
 Imports []ArchiveImportReport `json:"imports"`
 Before registry.ValidationReport `json:"before"`
 After *registry.ValidationReport `json:"after,omitempty"`
 FailedListingID string `json:"failedListingId,omitempty"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}

func selectArchiveBatch(endpoints []Endpoint,ids []string)([]string,error){
 if len(ids)==0||len(ids)>MaxArchiveBatch{return nil,errors.New("select 1 to 8 explicit archive listing IDs")}
 selected:=append([]string{},ids...)
 sort.Strings(selected)
 last:=""
 for _,id:=range selected{
  if id==last||!idPattern.MatchString(id){return nil,errors.New("invalid or duplicate listing ID")}
  last=id
  e,err:=archiveEndpoint(endpoints,id);if err!=nil{return nil,err}
  if e.PublishedSHA256==nil||!sha256Pattern.MatchString(e.PublishedSHA256.Fingerprint){return nil,errors.New("batch requires an independent published SHA-256 lead for each listing")}
 }
 return selected,nil
}

// AcquireArchivedBatch acquires only explicitly selected fixed endpoints.
// Each observation uses the existing exclusive lock and immutable archive.
// Existing valid observations are reused. No retries or implicit pin approval.
func AcquireArchivedBatch(ctx context.Context,dir string,ids []string)(ArchiveBatchFetchReport,error){
 c,err:=SHECA();if err!=nil{return ArchiveBatchFetchReport{},err}
 endpoints,err:=Endpoints();if err!=nil{return ArchiveBatchFetchReport{},err}
 client,closeClient:=newResearchClient();defer closeClient()
 return acquireArchivedBatch(ctx,client,c,endpoints,dir,ids)
}

func acquireArchivedBatch(ctx context.Context,client *http.Client,c Catalog,endpoints []Endpoint,dir string,ids []string)(ArchiveBatchFetchReport,error){
 if ctx==nil{return ArchiveBatchFetchReport{},errors.New("context required")}
 if err:=c.Validate();err!=nil{return ArchiveBatchFetchReport{},err}
 selected,err:=selectArchiveBatch(endpoints,ids);if err!=nil{return ArchiveBatchFetchReport{},err}
 if err:=archiveDir(dir);err!=nil{return ArchiveBatchFetchReport{},err}
 report:=ArchiveBatchFetchReport{Status:"INCOMPLETE_BATCH_ACQUISITION",RequestedIDs:selected,Receipts:[]ArchiveReceipt{},TrustStatus:"NOT_ESTABLISHED"}
 // Fail fast. Previously completed immutable observations remain available
 // for an explicit retry with the same private archive directory.
 for _,id:=range selected{
  if err:=ctx.Err();err!=nil{report.FailedListingID=id;return report,err}
  r,err:=acquireArchived(ctx,client,c,endpoints,dir,id,false)
  if err!=nil{report.FailedListingID=id;return report,fmt.Errorf("acquire %s: %w",id,err)}
  report.Receipts=append(report.Receipts,r)
  report.SuccessfulFetchOperations+=r.FetchOperations
 }
 report.Status="UNREVIEWED_BATCH_OBSERVATIONS_ARCHIVED"
 return report,nil
}

// ImportArchivedBatch validates all explicit independent pins, originals and
// the destination before the first write. No transaction or trust grant.
func ImportArchivedBatch(s *registry.Store,dir string,refs []AcquisitionArchiveReference)(ArchiveBatchImportReport,error){
 c,err:=SHECA();if err!=nil{return ArchiveBatchImportReport{},err}
 endpoints,err:=Endpoints();if err!=nil{return ArchiveBatchImportReport{},err}
 return importArchivedBatch(s,c,endpoints,dir,refs)
}

func importArchivedBatch(s *registry.Store,c Catalog,endpoints []Endpoint,dir string,refs []AcquisitionArchiveReference)(ArchiveBatchImportReport,error){
 if s==nil{return ArchiveBatchImportReport{},errors.New("initialized inventory required")}
 if err:=c.Validate();err!=nil{return ArchiveBatchImportReport{},err}
 if len(refs)==0||len(refs)>MaxArchiveBatch{return ArchiveBatchImportReport{},errors.New("select 1 to 8 independently pinned archive references")}
 ids:=make([]string,0,len(refs));pins:=map[string]string{}
 for _,ref:=range refs{
  if !sha256Pattern.MatchString(ref.SHA256){return ArchiveBatchImportReport{},errors.New("independent archive SHA-256 required")}
  ids=append(ids,ref.ListingID);pins[ref.ListingID]=ref.SHA256
 }
 selected,err:=selectArchiveBatch(endpoints,ids);if err!=nil{return ArchiveBatchImportReport{},err}
 if err:=archiveDir(dir);err!=nil{return ArchiveBatchImportReport{},err}
 type prepared struct{archive AcquisitionArchive;receipt ArchiveReceipt}
 items:=make([]prepared,0,len(selected))
 seen:=map[string]bool{}
 // Bounded by eight originals of <=1 MiB each; read each archive once.
 for _,id:=range selected{
  a,b,err:=readArchive(c,endpoints,dir,id,pins[id])
  if err!=nil{return ArchiveBatchImportReport{},fmt.Errorf("preflight %s: %w",id,err)}
  receipt:=makeArchiveReceipt(a,b,"PINNED_LOCAL_OBSERVATION_VERIFIED",0,true)
  if seen[receipt.CertificateSHA256]{return ArchiveBatchImportReport{},errors.New("duplicate certificate across archive selections")}
  seen[receipt.CertificateSHA256]=true
  items=append(items,prepared{a,receipt})
 }
 before,err:=s.Validate();if err!=nil{return ArchiveBatchImportReport{},err}
 report:=ArchiveBatchImportReport{Status:"INCOMPLETE_LOCAL_BATCH_IMPORT",RequestedIDs:selected,Before:before,Imports:[]ArchiveImportReport{},TrustStatus:"NOT_ESTABLISHED"}
 for _,v:=range items{
  a:=v.archive
  imported,err:=s.Import(a.Raw,a.Report.Preview.Provenance.SourceURL,a.RecordedAt)
  if err!=nil{report.FailedListingID=a.ListingID;return report,fmt.Errorf("import %s: %w",a.ListingID,err)}
  report.Imports=append(report.Imports,ArchiveImportReport{Receipt:v.receipt,Import:imported,Status:"LOCAL_IMPORT_WRITTEN_VALIDATION_PENDING",TrustStatus:"NOT_ESTABLISHED"})
 }
 after,err:=s.Validate();if err!=nil{return report,err}
 report.After=&after
 for i:=range report.Imports{report.Imports[i].Status="UNREVIEWED_ARCHIVED_CANDIDATE_IMPORTED"}
 report.Status="UNREVIEWED_ARCHIVED_BATCH_IMPORTED"
 return report,nil
}
