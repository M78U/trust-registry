package snapshot

import (
 "bytes"
 "errors"
 "sort"
 "strings"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/emmansun/gmsm/smx509"
)

const MaxConsumerCandidates=64
const MaxConsumerDERBytes=3<<20
const MaxConsumerBundleBytes=6<<20

type ConsumerCandidate struct {
 SHA256 string `json:"sha256"`
 DER []byte `json:"der"`
 ProvenanceIDs []string `json:"provenanceIds"`
}
type ConsumerBundle struct {
 SchemaVersion string `json:"schemaVersion"`
 Kind string `json:"kind"`
 SnapshotSHA256 string `json:"snapshotSHA256"`
 SnapshotSequence uint64 `json:"snapshotSequence"`
 Certificates []ConsumerCandidate `json:"certificates"`
}

// DiscoverIssuers exposes the existing direct issuer checks on a detached
// loaded snapshot. No source promotion or network.
func(v *Loaded)DiscoverIssuers(input []byte)(registry.DiscoveryReport,error){
 var result registry.DiscoveryReport
 err:=v.withStore(func(s *registry.Store)error{
  var err error
  result,err=s.DiscoverIssuers(input)
  return err
 })
 return result,err
}

// CandidateBundle exports only non-self-issued inventory CA candidates.
// With an input certificate, include only ancestors reachable through MATCHED
// graph edges. Without input, export all eligible candidates, within bounds.
// No input certificate bytes, anchors, policy decisions or trust claims.
func(v *Loaded)CandidateBundle(input []byte)([]byte,error){
 if v==nil||v.index==nil||v.sequence==0||!hashPattern.MatchString(v.snapshotSHA256){return nil,errors.New("loaded snapshot required")}
 var selected map[string]bool
 if input!=nil{
  record,_,err:=registry.ParseCertificate(input);if err!=nil{return nil,err}
  selected=map[string]bool{record.FingerprintSHA256:true}
  err=v.withStore(func(s *registry.Store)error{
   g,err:=s.BuildGraph(input);if err!=nil{return err}
   view,err:=g.Export();if err!=nil{return err}
   parents:=map[string][]string{}
   for _,e:=range view.Edges{if e.DirectIssuerStatus=="MATCHED"{parents[e.ChildSHA256]=append(parents[e.ChildSHA256],e.IssuerSHA256)}}
   queue:=[]string{record.FingerprintSHA256}
   for len(queue)>0{
    fp:=queue[0];queue=queue[1:]
    for _,parent:=range parents[fp]{if !selected[parent]{selected[parent]=true;queue=append(queue,parent)}}
   }
   delete(selected,record.FingerprintSHA256)
   return nil
  });if err!=nil{return nil,err}
 }
 bundle:=ConsumerBundle{"1","UNTRUSTED_CA_CANDIDATES",v.snapshotSHA256,v.sequence,[]ConsumerCandidate{}}
 total:=0
 for _,f:=range v.payload{
  if !strings.HasPrefix(f.Path,"certificates/")||!strings.HasSuffix(f.Path,".der"){continue}
  fp:=strings.TrimSuffix(strings.TrimPrefix(f.Path,"certificates/"),".der")
  if selected!=nil&&!selected[fp]{continue}
  if digest(f.Data)!=fp{return nil,errors.New("loaded candidate hash mismatch")}
  c,err:=smx509.ParseCertificate(f.Data);if err!=nil{return nil,err}
  if !bytes.Equal(c.RawSubject,c.RawIssuer)&&c.IsCA&&c.BasicConstraintsValid&&(c.KeyUsage==0||c.KeyUsage&smx509.KeyUsageCertSign!=0)&&len(c.UnhandledCriticalExtensions)==0{
   if len(bundle.Certificates)>=MaxConsumerCandidates||len(f.Data)>MaxConsumerDERBytes-total{return nil,errors.New("consumer candidate budget exceeded; select a certificate")}
   entries,err:=v.index.Provenance(fp);if err!=nil{return nil,err}
   ids:=make([]string,0,len(entries))
   for _,e:=range entries{ids=append(ids,e.ID)}
   if len(ids)>256{return nil,errors.New("candidate provenance budget exceeded")}
   sort.Strings(ids)
   bundle.Certificates=append(bundle.Certificates,ConsumerCandidate{fp,bytes.Clone(f.Data),ids})
   total+=len(f.Data)
  }
 }
 sort.Slice(bundle.Certificates,func(i,j int)bool{return bundle.Certificates[i].SHA256<bundle.Certificates[j].SHA256})
 raw,err:=canonical(bundle);if err!=nil{return nil,err}
 if len(raw)>MaxConsumerBundleBytes{return nil,errors.New("consumer bundle too large")}
 return raw,nil
}
