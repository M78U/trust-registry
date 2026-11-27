// Package aia provides explicit, single-hop research acquisition from
// certificate AIA caIssuers URLs. It never grants trust or fetches during
// ordinary offline verification.
package aia

import (
 "context"
 "crypto/sha256"
 "crypto/tls"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/netip"
 "net/url"
 "regexp"
 "sort"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/emmansun/gmsm/smx509"
)

const MaxURLs=16
const maxURLBytes=2048
const maxAddresses=16
var dnsLabel=regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var safePath=regexp.MustCompile(`^/[A-Za-z0-9._~/-]+$`)

func eligibleURL(raw string)(*url.URL,error){
 reject:=errors.New("AIA URL outside conservative HTTPS profile")
 if len(raw)==0||len(raw)>maxURLBytes||strings.ContainsAny(raw,"\\%?#"){return nil,reject}
 u,err:=url.Parse(raw)
 if err!=nil||u.Scheme!="https"||u.Opaque!=""||u.User!=nil||u.Host!=u.Hostname()||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.RawPath!=""||u.String()!=raw||!safePath.MatchString(u.Path)||strings.Contains(u.Path,"//"){return nil,reject}
 host:=u.Hostname()
 if len(host)>253||!strings.Contains(host,".")||net.ParseIP(host)!=nil{return nil,reject}
 for _,label:=range strings.Split(host,"."){if !dnsLabel.MatchString(label){return nil,reject}}
 if strings.HasSuffix(host,".localhost")||strings.HasSuffix(host,".local")||strings.HasSuffix(host,".internal")||strings.HasSuffix(host,".home.arpa"){return nil,reject}
 for _,seg:=range strings.Split(u.Path,"/"){if seg=="."||seg==".."{return nil,reject}}
 return u,nil
}
type Plan struct{
 CertificateSHA256 string `json:"certificateSHA256"`
 EligibleURLs []string `json:"eligibleURLs"`
 UnsupportedCount int `json:"unsupportedCount"`
 NetworkAttempted bool `json:"networkAttempted"`
 TrustStatus string `json:"trustStatus"`
}
// Inspect reads caIssuers only, never OCSP URLs, and does not perform DNS.
func Inspect(input []byte)(Plan,error){
 row,der,err:=registry.ParseCertificate(input);if err!=nil{return Plan{},err}
 c,err:=smx509.ParseCertificate(der);if err!=nil{return Plan{},err}
 if len(c.IssuingCertificateURL)>MaxURLs{return Plan{},errors.New("AIA URL count limit exceeded")}
 plan:=Plan{CertificateSHA256:row.FingerprintSHA256,EligibleURLs:[]string{},TrustStatus:"NOT_ESTABLISHED"}
 seen:=map[string]bool{}
 for _,raw:=range c.IssuingCertificateURL{
  if _,err:=eligibleURL(raw);err!=nil{plan.UnsupportedCount++;continue}
  if !seen[raw]{seen[raw]=true;plan.EligibleURLs=append(plan.EligibleURLs,raw)}
 }
 sort.Strings(plan.EligibleURLs)
 return plan,nil
}
func selectedURL(input []byte,raw string)(Plan,*url.URL,error){
 plan,err:=Inspect(input);if err!=nil{return Plan{},nil,err}
 for _,v:=range plan.EligibleURLs{if v==raw{u,err:=eligibleURL(raw);return plan,u,err}}
 return Plan{},nil,errors.New("select exact eligible caIssuers URL from local certificate")
}

// IPv4-only conservative public address policy. IsGlobalUnicast alone
// permits private and special-use IPs. These ranges are explicitly denied.
var denied=[]netip.Prefix{
 netip.MustParsePrefix("0.0.0.0/8"),netip.MustParsePrefix("10.0.0.0/8"),
 netip.MustParsePrefix("100.64.0.0/10"),netip.MustParsePrefix("127.0.0.0/8"),
 netip.MustParsePrefix("169.254.0.0/16"),netip.MustParsePrefix("172.16.0.0/12"),
 netip.MustParsePrefix("192.0.0.0/24"),netip.MustParsePrefix("192.0.2.0/24"),
 netip.MustParsePrefix("192.88.99.0/24"),netip.MustParsePrefix("192.168.0.0/16"),
 netip.MustParsePrefix("198.18.0.0/15"),netip.MustParsePrefix("198.51.100.0/24"),
 netip.MustParsePrefix("203.0.113.0/24"),netip.MustParsePrefix("224.0.0.0/3"),
}
func publicIPv4(a netip.Addr)bool{
 if !a.Is4()||!a.IsGlobalUnicast(){return false}
 for _,p:=range denied{if p.Contains(a){return false}}
 return true
}
type resolveFunc func(context.Context,string,string)([]netip.Addr,error)
type dialFunc func(context.Context,string,string)(net.Conn,error)
func pinnedDial(host string,lookup resolveFunc,dial dialFunc)dialFunc{
 return func(ctx context.Context,network,address string)(net.Conn,error){
  h,port,err:=net.SplitHostPort(address)
  if err!=nil||h!=host||port!="443"||network!="tcp"{return nil,errors.New("unexpected AIA dial target")}
  answers,err:=lookup(ctx,"ip4",host)
  if err!=nil||len(answers)==0||len(answers)>maxAddresses{return nil,errors.New("AIA DNS lookup failed or exceeds bound")}
  // Reject mixed public/private answers instead of silently choosing one.
  for _,a:=range answers{if !publicIPv4(a){return nil,errors.New("AIA DNS resolved to prohibited address")}}
  // Connect to the checked literal IP, never resolve the hostname again.
  // TLS verification still uses the original hostname.
  return dial(ctx,"tcp4",net.JoinHostPort(answers[0].String(),"443"))
 }
}
type Report struct{
 CertificateSHA256 string `json:"certificateSHA256"`
 URL string `json:"url"`
 Candidate registry.IssuerCandidate `json:"candidate"`
 SourceFileSHA256 string `json:"sourceFileSHA256"`
 AcquisitionStatus string `json:"acquisitionStatus"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
func Audit(child,candidate []byte,raw string)(Report,error){
 plan,_,err:=selectedURL(child,raw);if err!=nil{return Report{},err}
 row,err:=registry.MatchIssuer(child,candidate);if err!=nil{return Report{},err}
 sum:=sha256.Sum256(candidate)
 return Report{CertificateSHA256:plan.CertificateSHA256,URL:raw,Candidate:row,SourceFileSHA256:hex.EncodeToString(sum[:]),AcquisitionStatus:"LOCAL_INPUT_ONLY",TrustStatus:"NOT_ESTABLISHED"},nil
}
func fetch(ctx context.Context,client *http.Client,child []byte,raw string)([]byte,Report,error){
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,raw,nil);if err!=nil{return nil,Report{},err}
 req.Header.Set("Accept","application/pkix-cert, application/x-pem-file, application/octet-stream")
 resp,err:=client.Do(req);if err!=nil{return nil,Report{},errors.New("AIA HTTPS download failed")}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK{return nil,Report{},fmt.Errorf("AIA download returned HTTP %d",resp.StatusCode)}
 if resp.ContentLength>registry.MaxCertificateInput||resp.Uncompressed||(resp.Header.Get("Content-Encoding")!=""&&resp.Header.Get("Content-Encoding")!="identity"){return nil,Report{},errors.New("unsupported AIA response length or encoding")}
 data,err:=io.ReadAll(io.LimitReader(resp.Body,registry.MaxCertificateInput+1));if err!=nil{return nil,Report{},err}
 if len(data)>registry.MaxCertificateInput{return nil,Report{},errors.New("AIA response too large")}
 report,err:=Audit(child,data,raw);if err!=nil{return nil,Report{},err}
 if report.Candidate.DirectIssuerStatus!="MATCHED"{return nil,Report{},errors.New("downloaded certificate not a matched direct issuer")}
 report.AcquisitionStatus="DOWNLOADED_UNREVIEWED"
 return data,report,nil
}
// Fetch is single-hop, explicitly selected, HTTPS-only. It uses OS trust only
// for transport TLS, never to establish Registry certificate trust.
func Fetch(ctx context.Context,child []byte,raw string)([]byte,Report,error){
 _,u,err:=selectedURL(child,raw);if err!=nil{return nil,Report{},err}
 ctx,cancel:=context.WithTimeout(ctx,30*time.Second);defer cancel()
 dialer:=&net.Dialer{Timeout:10*time.Second}
 tr:=&http.Transport{
  DialContext:pinnedDial(u.Hostname(),net.DefaultResolver.LookupNetIP,dialer.DialContext),
  TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12,ServerName:u.Hostname()},
  DisableCompression:true,DisableKeepAlives:true,TLSHandshakeTimeout:10*time.Second,
  ResponseHeaderTimeout:15*time.Second,MaxResponseHeaderBytes:32768,
 }
 defer tr.CloseIdleConnections()
 client:=&http.Client{Transport:tr,Timeout:30*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("AIA redirects disabled")}}
 return fetch(ctx,client,child,raw)
}
