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
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
)

func TestPinnedArchiveBatch(t *testing.T){
 c,err:=SHECA();if err!=nil{t.Fatal(err)}
 endpoints,err:=Endpoints();if err!=nil{t.Fatal(err)}
 at:=time.Date(2026,11,27,0,0,0,0,time.UTC)
 ids:=[]string{"uca-global-g2","uca-sm2"}
 originals:=map[string][]byte{}
 for n,id:=range ids{
  k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
  tpl:=&x509.Certificate{SerialNumber:big.NewInt(int64(n+1)),Subject:pkix.Name{CommonName:id},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
  der,e:=x509.CreateCertificate(rand.Reader,tpl,tpl,&k.PublicKey,k);if e!=nil{t.Fatal(e)}
  h:=sha1.Sum(der)
  for j:=range c.Entries{if c.Entries[j].ID==id{c.Entries[j].PublishedSHA1=hex.EncodeToString(h[:])}}
  for j:=range endpoints{if endpoints[j].ListingID==id{
   v:=*endpoints[j].PublishedSHA256;v.Fingerprint=intakeHash(der);endpoints[j].PublishedSHA256=&v
   originals[endpoints[j].DownloadURL]=der
  }}
 }
 hits:=0
 failSecond:=true
 client:=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
  hits++
  b,ok:=originals[req.URL.String()];if !ok{t.Fatal("unexpected URL")}
  if hits==2&&failSecond{return &http.Response{StatusCode:404,Body:io.NopCloser(strings.NewReader("missing")),Header:make(http.Header)},nil}
  return &http.Response{StatusCode:200,Body:io.NopCloser(bytes.NewReader(b)),ContentLength:int64(len(b)),Header:make(http.Header)},nil
 })}
 dir:=t.TempDir()
 for _,bad:=range [][]string{nil,{ids[0],ids[0]},{ids[0],"../escape"},{ids[0],"uca-root-g2"}}{
  if _,err:=acquireArchivedBatch(context.Background(),client,c,endpoints,dir,bad);err==nil||hits!=0{t.Fatal("bad selection performed a request",bad)}
 }
 if entries,err:=os.ReadDir(dir);err!=nil||len(entries)!=0{t.Fatal(entries,err)}
 r,err:=acquireArchivedBatch(context.Background(),client,c,endpoints,dir,[]string{ids[1],ids[0]})
 if err==nil||r.Status!="INCOMPLETE_BATCH_ACQUISITION"||len(r.Receipts)!=1||r.FailedListingID!=ids[1]||r.SuccessfulFetchOperations!=1||hits!=2{t.Fatal(r,err,hits)}
 failSecond=false
 r2,err:=acquireArchivedBatch(context.Background(),client,c,endpoints,dir,ids)
 if err!=nil||r2.Status!="UNREVIEWED_BATCH_OBSERVATIONS_ARCHIVED"||len(r2.Receipts)!=2||r2.SuccessfulFetchOperations!=1||r2.Receipts[0].ArchiveSHA256!=r.Receipts[0].ArchiveSHA256||r2.Receipts[0].PinMatched||hits!=3{t.Fatal(r2,err,hits)}
 r3,err:=acquireArchivedBatch(context.Background(),client,c,endpoints,dir,ids)
 if err!=nil||r3.SuccessfulFetchOperations!=0||hits!=3{t.Fatal(r3,err,hits)}
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 if _,err:=s.Init();err!=nil{t.Fatal(err)}
 refs:=[]AcquisitionArchiveReference{{ListingID:ids[1],SHA256:r2.Receipts[1].ArchiveSHA256},{ListingID:ids[0],SHA256:r2.Receipts[0].ArchiveSHA256}}
 bad:=append([]AcquisitionArchiveReference{},refs...);bad[0].SHA256=strings.Repeat("0",64)
 if _,err:=importArchivedBatch(s,c,endpoints,dir,bad);err==nil{t.Fatal("bad second pin accepted")}
 if v,err:=s.Validate();err!=nil||v.Certificates!=0||v.ProvenanceRecords!=0{t.Fatal("preflight wrote inventory",v,err)}
 if _,err:=importArchivedBatch(s,c,endpoints,dir,[]AcquisitionArchiveReference{refs[0],refs[0]});err==nil{t.Fatal("duplicate accepted")}
 for j:=0;j<2;j++{
  v,err:=importArchivedBatch(s,c,endpoints,dir,refs)
  if err!=nil||v.Status!="UNREVIEWED_ARCHIVED_BATCH_IMPORTED"||v.After==nil||v.After.Certificates!=2||v.After.ProvenanceRecords!=2||len(v.Imports)!=2||v.ReleaseAuthenticated||v.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(v,err)}
  for n,item:=range v.Imports{if !item.Receipt.PinMatched||item.Receipt.ListingID!=ids[n]||item.Receipt.ArchiveSHA256!=r2.Receipts[n].ArchiveSHA256||item.Import.Provenance.SourceFileSHA256!=item.Receipt.SourceFileSHA256||item.Import.Provenance.ReviewStatus!="CANDIDATE"{t.Fatal(item)}}
 }
}
