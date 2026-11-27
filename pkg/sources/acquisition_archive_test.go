package sources

import (
 "bytes"
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha1"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/hex"
 "io"
 "math/big"
 "net/http"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
)

func TestAcquisitionArchiveReuseAndImport(t *testing.T){
 now:=time.Now().UTC().Truncate(time.Second)
 k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 tmpl:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic archive CA"},NotBefore:now.Add(-time.Hour),NotAfter:now.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 der,err:=x509.CreateCertificate(rand.Reader,tmpl,tmpl,&k.PublicKey,k);if err!=nil{t.Fatal(err)}
 c,err:=SHECA();if err!=nil{t.Fatal(err)}
 endpoints,err:=Endpoints();if err!=nil{t.Fatal(err)}
 e:=endpoints[0]
 h:=sha1.Sum(der)
 for i:=range c.Entries{if c.Entries[i].ID==e.ListingID{c.Entries[i].PublishedSHA1=hex.EncodeToString(h[:])}}
 e.PublishedSHA256=&FingerprintEvidence{intakeHash(der),"https://example.org/evidence","SYNTHETIC"}
 endpoints[0]=e
 hits:=0
 client:=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
  hits++
  if req.Method!="GET"||req.URL.String()!=e.DownloadURL{t.Fatal("unexpected acquisition")}
  return &http.Response{StatusCode:200,Body:io.NopCloser(bytes.NewReader(der)),ContentLength:int64(len(der)),Header:make(http.Header)},nil
 })}
 ctx:=context.Background();dir:=t.TempDir()
 acquire:=func()(ArchiveReceipt,error){return acquireArchived(ctx,client,c,endpoints,dir,e.ListingID,false)}
 first,err:=acquire()
 if err!=nil||first.FetchOperations!=1||hits!=1||first.PinMatched||first.ReleaseAuthenticated||first.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(first,err)}
 again,err:=acquire()
 if err!=nil||again.FetchOperations!=0||hits!=1||again.ArchiveSHA256!=first.ArchiveSHA256||!again.RecordedAt.Equal(first.RecordedAt){t.Fatal(again,err)}
 a,raw,err:=readArchive(c,endpoints,dir,e.ListingID,first.ArchiveSHA256)
 if err!=nil||!bytes.Equal(a.Raw,der)||a.Report.Preview.Provenance.SourceURL!=e.DownloadURL||a.Report.Preview.Provenance.SourceFileSHA256!=intakeHash(der){t.Fatal(a.Report,err)}
 if _,_,err:=readArchive(c,endpoints,dir,e.ListingID,strings.Repeat("0",64));err==nil{t.Fatal("wrong pin accepted")}
 lock:=filepath.Join(dir,e.ListingID+".lock")
 if err:=os.Mkdir(lock,0700);err!=nil{t.Fatal(err)}
 if _,err:=acquire();err==nil||hits!=1{t.Fatal("concurrent acquisition allowed")}
 if err:=os.Remove(lock);err!=nil{t.Fatal(err)}
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 m,err:=MultiCA();if err!=nil{t.Fatal(err)}
 options:=AcquisitionArchiveOptions{ArchiveDir:dir,Archives:[]AcquisitionArchiveReference{{ListingID:e.ListingID,SHA256:first.ArchiveSHA256}}}
 checkCoverage:=func(want int){
  t.Helper()
  idx,err:=s.BuildIndex();if err!=nil{t.Fatal(err)}
  coverage,err:=acquisitionCoverage(c,endpoints,m,idx);if err!=nil{t.Fatal(err)}
  if err:=attachArchiveCoverage(&coverage,c,endpoints,m,idx,options);err!=nil{t.Fatal(err)}
  v:=coverage.ArchiveCoverage
  if v==nil||v.CheckedArchives!=1||v.MatchedArchives!=want||v.MatchedProvenanceRecords!=want||coverage.ReleaseAuthenticated{t.Fatal(v)}
  for _,row:=range coverage.Tasks{if row.ListingID==e.ListingID{
   expected:="PINNED_ARCHIVE_CHECKED";if want==1{expected="PINNED_ARCHIVE_MATCHED_PROVENANCE"}
   if row.ArchiveStatus!=expected{t.Fatal(row)}
   return
  }}
  t.Fatal("missing row")
 }
 checkCoverage(0)
 // Same fingerprint and source URL, but a different observation time,
 // must not satisfy exact canonical provenance matching.
 if _,err:=s.Import(der,e.DownloadURL,first.RecordedAt.Add(time.Second));err!=nil{t.Fatal(err)}
 checkCoverage(0)
 imported,err:=importArchived(s,c,endpoints,dir,e.ListingID,first.ArchiveSHA256)
 if err!=nil||imported.Status!="UNREVIEWED_ARCHIVED_CANDIDATE_IMPORTED"||!imported.Receipt.PinMatched||!imported.Import.Provenance.RecordedAt.Equal(first.RecordedAt)||imported.Import.Provenance.ReviewStatus!="CANDIDATE"{t.Fatal(imported,err)}
 retry,err:=importArchived(s,c,endpoints,dir,e.ListingID,first.ArchiveSHA256)
 if err!=nil||retry.Import.ProvenanceID!=imported.Import.ProvenanceID{t.Fatal(retry,err)}
 checkCoverage(1)
 counts,err:=s.Validate();if err!=nil||counts.Certificates!=1||counts.ProvenanceRecords!=2{t.Fatal(counts,err)}
 altered:=append([]Endpoint{},endpoints...);altered[0].ObservedOn="2026-11-26"
 if altered[0].ObservedOn==endpoints[0].ObservedOn{altered[0].ObservedOn="2026-11-25"}
 if _,err:=acquireArchived(ctx,client,c,altered,dir,e.ListingID,false);err==nil||hits!=1{t.Fatal("changed catalog caused silent reuse or fetch")}
 path:=filepath.Join(dir,e.ListingID+".json")
 if err:=os.WriteFile(path,append(bytes.Clone(raw),'\n'),0600);err!=nil{t.Fatal(err)}
 if _,err:=acquire();err==nil||hits!=1{t.Fatal("corrupt archive silently fetched")}
 if _,err:=importArchived(s,c,endpoints,dir,e.ListingID,first.ArchiveSHA256);err==nil{t.Fatal("tampered archive imported")}
 idx,err:=s.BuildIndex();if err!=nil{t.Fatal(err)}
 coverage,err:=acquisitionCoverage(c,endpoints,m,idx);if err!=nil{t.Fatal(err)}
 if err:=attachArchiveCoverage(&coverage,c,endpoints,m,idx,options);err==nil{t.Fatal("tampered archive counted")}
 if _,err:=acquireArchived(ctx,client,c,endpoints,dir,"../escape",false);err==nil||hits!=1{t.Fatal("unknown endpoint accepted")}
}
func TestAcquisitionArchiveFailureLeavesNoRecord(t *testing.T){
 c,err:=SHECA();if err!=nil{t.Fatal(err)}
 endpoints,err:=Endpoints();if err!=nil{t.Fatal(err)}
 var e Endpoint;for _,v:=range endpoints{if v.PublishedSHA256!=nil{e=v;break}}
 dir:=t.TempDir()
 client:=&http.Client{Transport:roundTripFunc(func(*http.Request)(*http.Response,error){
  return &http.Response{StatusCode:404,Body:io.NopCloser(strings.NewReader("missing")),Header:make(http.Header)},nil
 })}
 if _,err:=acquireArchived(context.Background(),client,c,endpoints,dir,e.ListingID,false);err==nil{t.Fatal("failed request archived")}
 entries,err:=os.ReadDir(dir);if err!=nil||len(entries)!=0{t.Fatal(entries,err)}
}
