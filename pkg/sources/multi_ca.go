package sources

import (
 _ "embed"
 "encoding/json"
 "errors"
 "fmt"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/emmansun/gmsm/smx509"
)

//go:embed multi-ca.json
var multiCAJSON []byte

type MultiCAEntry struct {
 ID string `json:"id"`
 Authority string `json:"authority"`
 Label string `json:"label"`
 Kind string `json:"kind"`
 Track string `json:"track"`
 SourceURL string `json:"sourceURL"`
 SourceStatus string `json:"sourceStatus"`
 PublishedSHA256 *FingerprintEvidence `json:"publishedSHA256,omitempty"`
 RedistributionStatus string `json:"redistributionStatus"`
}
type MultiCACatalog struct {
 SchemaVersion string `json:"schemaVersion"`
 ObservedOn string `json:"observedOn"`
 Coverage string `json:"coverage"`
 TrustStatus string `json:"trustStatus"`
 Entries []MultiCAEntry `json:"entries"`
}
func MultiCA()(MultiCACatalog,error){
 var c MultiCACatalog
 if err:=json.Unmarshal(multiCAJSON,&c);err!=nil{return c,err}
 if err:=c.Validate();err!=nil{return MultiCACatalog{},err}
 return c,nil
}
func (c MultiCACatalog)Validate()error{
 if c.SchemaVersion!="1"||c.Coverage!="SELECTED_RESEARCH_LEADS"||c.TrustStatus!="NOT_ESTABLISHED"||len(c.Entries)==0||len(c.Entries)>256{return errors.New("invalid multi-CA research catalog")}
 if _,err:=time.Parse(time.DateOnly,c.ObservedOn);err!=nil{return err}
 last:=""
 fingerprints:=map[string]bool{}
 for _,e:=range c.Entries{
  if !idPattern.MatchString(e.ID)||e.ID<=last||e.Label==""||len(e.Label)>256||e.RedistributionStatus!="NOT_REVIEWED"{return errors.New("invalid or duplicate multi-CA listing")}
  last=e.ID
  switch e.Authority{
  case "CFCA":
   if e.SourceURL!="https://www.cfca.com.cn/zhengshuzizhu/"{return errors.New("unexpected CFCA source")}
  case "BJCA":
   if e.SourceURL!="https://www.bjca.cn/service/down_198.html"&&e.SourceURL!="https://repo.bjca.cn/global/cert/"{return errors.New("unexpected BJCA source")}
  case "GDCA":
   if e.SourceURL!="https://www.gdca.com.cn/customer_service/knowledge_universe/ca_cq/"{return errors.New("unexpected GDCA source")}
  default:return errors.New("unknown authority")
  }
  switch e.SourceStatus{case "OFFICIAL_PAGE_OBSERVED","OFFICIAL_SEARCH_INDEX_ONLY","OFFICIAL_RELATED_POLICY_PAGE":default:return errors.New("invalid observation status")}
  switch e.Kind{case "CHAIN_LISTING","CERTIFICATE_NAME_LEAD":default:return errors.New("invalid listing kind")}
  switch e.Track{case "GENERAL","SM2","DOCUMENT_SIGNING","TIMESTAMPING":default:return errors.New("unknown research track")}
  if f:=e.PublishedSHA256;f!=nil{
   if e.Kind!="CERTIFICATE_NAME_LEAD"||!sha256Pattern.MatchString(f.Fingerprint)||fingerprints[f.Fingerprint]{return errors.New("invalid or duplicate published SHA-256 lead")}
   fingerprints[f.Fingerprint]=true
   switch f.Scope{
   case "MICROSOFT_DOCUMENT_SIGNING_LIST":
    if e.Authority!="CFCA"||f.SourceURL!="https://ccadb.my.salesforce-sites.com/microsoft/includedcacertificatereportformsft"{return errors.New("unexpected Microsoft lead")}
   case "MOZILLA_ROOT_INCLUSION_RECORD":
    if e.Authority!="BJCA"||f.SourceURL!="https://bugzilla.mozilla.org/show_bug.cgi?id=1822921"{return errors.New("unexpected Mozilla lead")}
   case "HUAWEI_SM_ROOT_LIST":
    if (e.Authority!="BJCA"&&e.Authority!="GDCA")||f.SourceURL!="https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-sm-root-certificate-20261030"{return errors.New("unexpected SM root lead")}
   case "HUAWEI_ROOT_LIST":
    if e.Authority!="GDCA"||f.SourceURL!="https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-root-certificate-20261030"{return errors.New("unexpected root lead")}
   default:return errors.New("unknown fingerprint lead scope")
   }
  }
 }
 return nil
}
func(c MultiCACatalog)Find(id string)(MultiCAEntry,error){
 for _,e:=range c.Entries{if e.ID==id{return e,nil}}
 return MultiCAEntry{},errors.New("unknown multi-CA listing")
}
func(c MultiCACatalog)Filter(authority string)(MultiCACatalog,error){
 if authority==""{return c,nil}
 if authority!="CFCA"&&authority!="BJCA"&&authority!="GDCA"{return MultiCACatalog{},errors.New("authority must be CFCA, BJCA or GDCA")}
 filtered:=[]MultiCAEntry{}
 for _,e:=range c.Entries{if e.Authority==authority{filtered=append(filtered,e)}}
 c.Entries=filtered
 return c,nil
}
type MultiCAAudit struct {
 Listing MultiCAEntry `json:"listing"`
 Certificate registry.CertificateRecord `json:"certificate"`
 Analysis CertificateAnalysis `json:"analysis"`
 OriginalSHA256 string `json:"originalSHA256"`
 FingerprintStatus string `json:"fingerprintStatus"`
 TrustStatus string `json:"trustStatus"`
 RegistryImported bool `json:"registryImported"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
// AuditMultiCA compares exact local bytes against a selected published digest
// and common name, not an asserted download URL. No network or store writes.
func AuditMultiCA(id string,input []byte)(MultiCAAudit,error){
 c,err:=MultiCA();if err!=nil{return MultiCAAudit{},err}
 return auditMultiCA(c,id,input)
}
func auditMultiCA(c MultiCACatalog,id string,input []byte)(MultiCAAudit,error){
 if err:=c.Validate();err!=nil{return MultiCAAudit{},err}
 e,err:=c.Find(id);if err!=nil{return MultiCAAudit{},err}
 if e.Kind!="CERTIFICATE_NAME_LEAD"||e.PublishedSHA256==nil{return MultiCAAudit{},errors.New("no exact published certificate fingerprint lead; research required")}
 rec,der,err:=registry.ParseCertificate(input);if err!=nil{return MultiCAAudit{},err}
 if !rec.IsCA||rec.FingerprintSHA256!=e.PublishedSHA256.Fingerprint{return MultiCAAudit{},fmt.Errorf("CA classification or published SHA-256 mismatch for %s",id)}
 cert,err:=smx509.ParseCertificate(der);if err!=nil{return MultiCAAudit{},err}
 if cert.Subject.CommonName!=e.Label||!cert.BasicConstraintsValid{return MultiCAAudit{},errors.New("certificate common name or basic constraints mismatch")}
 analysis,err:=analyze(input);if err!=nil{return MultiCAAudit{},err}
 return MultiCAAudit{Listing:e,Certificate:rec,Analysis:analysis,OriginalSHA256:intakeHash(input),FingerprintStatus:"MATCHED_PUBLISHED_LEAD",TrustStatus:"NOT_ESTABLISHED"},nil
}
