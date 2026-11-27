package aia

import (
 "bytes"
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "errors"
 "io"
 "math/big"
 "net"
 "net/http"
 "net/netip"
 "strings"
 "testing"
 "time"
)

const endpoint="https://ca.example.org/issuer.cer"
func fixture(t *testing.T)([]byte,[]byte){
 t.Helper()
 at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 root:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic issuer"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 rd,err:=x509.CreateCertificate(rand.Reader,root,root,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
 parsed,err:=x509.ParseCertificate(rd);if err!=nil{t.Fatal(err)}
 leaf:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic signer"},NotBefore:at,NotAfter:at.AddDate(1,0,0),IssuingCertificateURL:[]string{endpoint,endpoint,"http://ca.example.org/issuer.cer"},OCSPServer:[]string{"https://ca.example.org/ocsp"},KeyUsage:x509.KeyUsageDigitalSignature}
 ld,err:=x509.CreateCertificate(rand.Reader,leaf,parsed,&k.PublicKey,key);if err!=nil{t.Fatal(err)}
 return ld,rd
}
func TestInspectAndAudit(t *testing.T){
 child,parent:=fixture(t)
 plan,err:=Inspect(child);if err!=nil||plan.NetworkAttempted||len(plan.EligibleURLs)!=1||plan.EligibleURLs[0]!=endpoint||plan.UnsupportedCount!=1{t.Fatal(plan,err)}
 r,err:=Audit(child,parent,endpoint);if err!=nil||r.Candidate.DirectIssuerStatus!="MATCHED"||r.TrustStatus!="NOT_ESTABLISHED"||r.ReleaseAuthenticated{t.Fatal(r,err)}
 if _,err:=Audit(child,parent,"https://ca.example.org/ocsp");err==nil{t.Fatal("non-caIssuers URL accepted")}
 _,wrong:=fixture(t)
 v,err:=Audit(child,wrong,endpoint);if err==nil&&v.Candidate.DirectIssuerStatus=="MATCHED"{t.Fatal("wrong issuer matched")}
}
func TestURLAndDNSBoundary(t *testing.T){
 for _,v:=range []string{"http://ca.example.org/a","https://127.0.0.1/a","https://[::1]/a","https://ca.example.org:443/a","https://user@ca.example.org/a","https://ca.example.org/a?token=1","https://ca.example.org/a#","https://ca.example.org/%2e%2e/a","https://ca.example.org/../a","https://ca.example.org/a//b","https://ca.local/a"}{if _,err:=eligibleURL(v);err==nil{t.Fatal("accepted",v)}}
 for _,v:=range []string{"127.0.0.1","169.254.169.254","10.0.0.1","100.64.0.1","172.16.0.1","192.168.1.1","192.0.2.1","198.18.0.1","224.0.0.1","240.0.0.1","::1","::ffff:8.8.8.8","2001:db8::1"}{if publicIPv4(netip.MustParseAddr(v)){t.Fatal("accepted",v)}}
 calls:=0
 dial:=func(_ context.Context,n,a string)(net.Conn,error){calls++;if n!="tcp4"||a!="8.8.8.8:443"{t.Fatal(n,a)};return nil,errors.New("test stop")}
 lookup:=func(_ context.Context,n,h string)([]netip.Addr,error){if n!="ip4"||h!="ca.example.org"{t.Fatal(n,h)};return []netip.Addr{netip.MustParseAddr("8.8.8.8"),netip.MustParseAddr("127.0.0.1")},nil}
 f:=pinnedDial("ca.example.org",lookup,dial)
 if _,err:=f(context.Background(),"tcp","ca.example.org:443");err==nil||calls!=0{t.Fatal("mixed DNS answers reached dial")}
 f=pinnedDial("ca.example.org",func(context.Context,string,string)([]netip.Addr,error){return []netip.Addr{netip.MustParseAddr("8.8.8.8")},nil},dial)
 _,_=f(context.Background(),"tcp","evil.example.org:443");if calls!=0{t.Fatal("wrong host")}
 _,_=f(context.Background(),"tcp","ca.example.org:443");if calls!=1{t.Fatal("not pinned")}
}
type transportFunc func(*http.Request)(*http.Response,error)
func(f transportFunc)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}
func TestFetchResponse(t *testing.T){
 child,parent:=fixture(t)
 for _,tc:=range []struct{code int;encoding string;body []byte;want bool}{{200,"",parent,true},{302,"",parent,false},{200,"gzip",parent,false},{200,"",[]byte("html"),false},{200,"",bytes.Repeat([]byte{'a'},(1<<20)+1),false}}{
  client:=&http.Client{Transport:transportFunc(func(r *http.Request)(*http.Response,error){
   if r.Method!="GET"||r.URL.String()!=endpoint||r.Body!=nil||r.Header.Get("Authorization")!=""||r.Header.Get("Cookie")!=""{t.Fatal("unexpected request")}
   h:=make(http.Header);if tc.encoding!=""{h.Set("Content-Encoding",tc.encoding)}
   return &http.Response{StatusCode:tc.code,Header:h,Body:io.NopCloser(strings.NewReader(string(tc.body))),ContentLength:-1},nil
  }),CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("disabled")}}
  raw,r,err:=fetch(context.Background(),client,child,endpoint)
  if (err==nil)!=tc.want{t.Fatal(tc.code,tc.encoding,err)}
  if tc.want&&(!bytes.Equal(raw,parent)||r.AcquisitionStatus!="DOWNLOADED_UNREVIEWED"){t.Fatal(r)}
 }
}
