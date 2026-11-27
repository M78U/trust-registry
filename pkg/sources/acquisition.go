package sources

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/emmansun/gmsm/smx509"
)

//go:embed sheca-endpoints.json
var endpointsJSON []byte

const endpointHost = "alvin-oss-test.oss-cn-hangzhou.aliyuncs.com"
const auxiliaryListing = "https://www.imtrust.cn/jishuwendang/dmqmwd/96.html"

type FingerprintEvidence struct {
	Fingerprint string `json:"fingerprint"`
	SourceURL string `json:"sourceURL"`
	Scope string `json:"scope"`
}

type Endpoint struct {
	ListingID string `json:"listingId"`
	DownloadURL string `json:"downloadURL"`
	ListingURL string `json:"listingURL"`
	ObservedOn string `json:"observedOn"`
	PublishedSHA256 *FingerprintEvidence `json:"publishedSHA256,omitempty"`
}

// Endpoints returns the reviewed research link observations, not trusted roots.
func Endpoints() ([]Endpoint,error) {
	c,err:=SHECA();if err!=nil{return nil,err}
	var entries []Endpoint
	if err:=json.Unmarshal(endpointsJSON,&entries);err!=nil{return nil,err}
	seen:=map[string]bool{}
	for _,e:=range entries {
		if _,err:=c.Find(e.ListingID);err!=nil{return nil,err}
		u,err:=url.Parse(e.DownloadURL)
		if err!=nil || u.Scheme!="https" || u.Host!=endpointHost || u.User!=nil || u.RawQuery!="" || u.ForceQuery || u.Fragment!="" || !strings.HasSuffix(u.Path,".cer") || e.ListingURL!=auxiliaryListing || seen[e.ListingID] {return nil,errors.New("invalid or duplicate acquisition endpoint")}
		if _,err:=time.Parse(time.DateOnly,e.ObservedOn);err!=nil{return nil,err}
		if ev:=e.PublishedSHA256;ev!=nil {
			if !sha256Pattern.MatchString(ev.Fingerprint) || ev.SourceURL=="" || ev.Scope=="" {return nil,errors.New("invalid published SHA-256 evidence")}
		}
		seen[e.ListingID]=true
	}
	return entries,nil
}

func findEndpoint(id string)(Endpoint,error){
	entries,err:=Endpoints();if err!=nil{return Endpoint{},err}
	for _,e:=range entries{if e.ListingID==id{return e,nil}}
	return Endpoint{},errors.New("no observed download endpoint for listing")
}

type CertificateAnalysis struct {
	SelfIssued bool `json:"selfIssued"`
	SelfSignatureStatus string `json:"selfSignatureStatus"`
	BasicConstraintsValid bool `json:"basicConstraintsValid"`
	KeyUsageBits int `json:"keyUsageBits"`
	ExtendedKeyUsageCodes []int `json:"extendedKeyUsageCodes"`
	UnknownExtendedKeyUsageOIDs []string `json:"unknownExtendedKeyUsageOids"`
	PolicyIdentifiers []string `json:"policyIdentifiers"`
	UnhandledCriticalExtensionOIDs []string `json:"unhandledCriticalExtensionOids"`
	MaxPathLen int `json:"maxPathLen"`
	MaxPathLenZero bool `json:"maxPathLenZero"`
}

func analyze(input []byte)(CertificateAnalysis,error){
	_,der,err:=registry.ParseCertificate(input);if err!=nil{return CertificateAnalysis{},err}
	c,err:=smx509.ParseCertificate(der);if err!=nil{return CertificateAnalysis{},err}
	a:=CertificateAnalysis{SelfIssued:bytes.Equal(c.RawSubject,c.RawIssuer),SelfSignatureStatus:"NOT_CHECKED_NOT_SELF_ISSUED",BasicConstraintsValid:c.BasicConstraintsValid,KeyUsageBits:int(c.KeyUsage),ExtendedKeyUsageCodes:[]int{},UnknownExtendedKeyUsageOIDs:[]string{},PolicyIdentifiers:[]string{},UnhandledCriticalExtensionOIDs:[]string{},MaxPathLen:c.MaxPathLen,MaxPathLenZero:c.MaxPathLenZero}
	if a.SelfIssued {
		a.SelfSignatureStatus="NOT_VERIFIED"
		if err:=c.CheckSignature(c.SignatureAlgorithm,c.RawTBSCertificate,c.Signature);err==nil{a.SelfSignatureStatus="VERIFIED"}
	}
	for _,v:=range c.ExtKeyUsage{a.ExtendedKeyUsageCodes=append(a.ExtendedKeyUsageCodes,int(v))}
	for _,v:=range c.UnknownExtKeyUsage{a.UnknownExtendedKeyUsageOIDs=append(a.UnknownExtendedKeyUsageOIDs,v.String())}
	for _,v:=range c.PolicyIdentifiers{a.PolicyIdentifiers=append(a.PolicyIdentifiers,v.String())}
	for _,v:=range c.UnhandledCriticalExtensions{a.UnhandledCriticalExtensionOIDs=append(a.UnhandledCriticalExtensionOIDs,v.String())}
	return a,nil
}

type AcquisitionReport struct {
	Endpoint Endpoint `json:"endpoint"`
	Preview IntakePreview `json:"preview"`
	Analysis CertificateAnalysis `json:"analysis"`
	AcquisitionStatus string `json:"acquisitionStatus"`
	PublishedSHA256Status string `json:"publishedSHA256Status"`
	OriginalFileSaved bool `json:"originalFileSaved"`
	RegistryImported bool `json:"registryImported"`
	TrustStatus string `json:"trustStatus"`
}

func inspectEndpoint(c Catalog,e Endpoint,input []byte,at time.Time)(AcquisitionReport,error){
	expected:=""
	if e.PublishedSHA256!=nil{expected=e.PublishedSHA256.Fingerprint}
	preview,err:=c.Preview(e.ListingID,input,expected,at);if err!=nil{return AcquisitionReport{},err}
	a,err:=analyze(input);if err!=nil{return AcquisitionReport{},err}
	status:="NOT_AVAILABLE"
	if expected!=""{status="MATCHED_PUBLISHED_FINGERPRINT"}
	return AcquisitionReport{Endpoint:e,Preview:preview,Analysis:a,AcquisitionStatus:"LOCAL_INPUT_ONLY",PublishedSHA256Status:status,TrustStatus:"NOT_ESTABLISHED"},nil
}

// InspectEndpoint compares local bytes with the pinned listing and available
// third-party fingerprint claims; it does not claim where the bytes came from.
func InspectEndpoint(id string,input []byte,at time.Time)(AcquisitionReport,error){
	e,err:=findEndpoint(id);if err!=nil{return AcquisitionReport{},err}
	c,err:=SHECA();if err!=nil{return AcquisitionReport{},err}
	return inspectEndpoint(c,e,input,at)
}

// Fetch is an explicit research acquisition, not a verification-time network
// fallback. Only embedded endpoints are requested. TLS transport uses normal
// platform TLS verification, unrelated to the registry's certificate trust.
func Fetch(ctx context.Context,id,outPath string,allowLegacyOnly bool)(AcquisitionReport,error){
	e,err:=findEndpoint(id);if err!=nil{return AcquisitionReport{},err}
	c,err:=SHECA();if err!=nil{return AcquisitionReport{},err}
	if outPath==""{return AcquisitionReport{},errors.New("output file is required")}
	if e.PublishedSHA256==nil&&!allowLegacyOnly{return AcquisitionReport{},errors.New("no published SHA-256; explicit legacy-only research opt-in required")}
	if _,err:=os.Lstat(outPath);err==nil{return AcquisitionReport{},errors.New("output already exists")}else if !os.IsNotExist(err){return AcquisitionReport{},err}
	tr:=&http.Transport{TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},DisableCompression:true,ResponseHeaderTimeout:15*time.Second}
	defer tr.CloseIdleConnections()
	client:=&http.Client{Transport:tr,Timeout:30*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("redirects disabled")}}
	input,report,err:=fetchBytes(ctx,client,c,e,allowLegacyOnly)
	if err!=nil{return AcquisitionReport{},err}
	f,err:=os.OpenFile(outPath,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return AcquisitionReport{},err}
	if _,err=f.Write(input);err==nil{err=f.Sync()}
	closeErr:=f.Close()
	if err==nil{err=closeErr}
	if err!=nil{_ = os.Remove(outPath);return AcquisitionReport{},err}
	report.OriginalFileSaved=true
	return report,nil
}

func fetchBytes(ctx context.Context,client *http.Client,c Catalog,e Endpoint,allowLegacyOnly bool)([]byte,AcquisitionReport,error){
	if e.PublishedSHA256==nil&&!allowLegacyOnly{return nil,AcquisitionReport{},errors.New("legacy-only acquisition not enabled")}
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,e.DownloadURL,nil);if err!=nil{return nil,AcquisitionReport{},err}
	req.Header.Set("Accept","application/pkix-cert, application/x-pem-file, application/octet-stream, text/plain")
	resp,err:=client.Do(req);if err!=nil{return nil,AcquisitionReport{},err}
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK{return nil,AcquisitionReport{},fmt.Errorf("download returned HTTP %d",resp.StatusCode)}
	if resp.ContentLength>registry.MaxCertificateInput || resp.Uncompressed || (resp.Header.Get("Content-Encoding")!=""&&resp.Header.Get("Content-Encoding")!="identity"){return nil,AcquisitionReport{},errors.New("unsupported download length or encoding")}
	input,err:=io.ReadAll(io.LimitReader(resp.Body,registry.MaxCertificateInput+1));if err!=nil{return nil,AcquisitionReport{},err}
	if len(input)>registry.MaxCertificateInput{return nil,AcquisitionReport{},errors.New("certificate download exceeds size limit")}
	at:=time.Now().UTC()
	report,err:=inspectEndpoint(c,e,input,at);if err!=nil{return nil,AcquisitionReport{},err}
	// The source now identifies the observed download URL rather than the
	// catalog page. Preserve the original bytes hash and unreviewed status.
	_,provenance,_,err:=registry.ImportCandidate(input,e.DownloadURL,at);if err!=nil{return nil,AcquisitionReport{},err}
	report.Preview.Provenance=provenance
	report.AcquisitionStatus="DOWNLOADED_UNREVIEWED"
	return input,report,nil
}
