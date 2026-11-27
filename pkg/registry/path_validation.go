package registry

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

const MaxVerificationCAs = 256

type PathOptions struct {
	AnchorFingerprints []string
	IntermediateFingerprints []string
	At time.Time
	Profile string
	DNSName string
}

type PathValidationReport struct {
	LeafSHA256 string `json:"leafSHA256"`
	EvaluationTime time.Time `json:"evaluationTime"`
	Profile string `json:"profile"`
	PathStatus string `json:"pathStatus"`
	UsageStatus string `json:"usageStatus"`
	RevocationStatus string `json:"revocationStatus"`
	TrustStatus string `json:"trustStatus"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
	Chains [][]string `json:"chains"`
	Reason string `json:"reason,omitempty"`
}

// VerifyPath checks a single ephemeral end-entity certificate against explicit
// local CA fingerprints. No system roots, AIA, revocation or authenticated
// trust authorization. Generic signature is only a technical profile.
func (s *Store) VerifyPath(input []byte,o PathOptions)(PathValidationReport,error){
	if o.At.IsZero()||o.At.Location()!=time.UTC||o.At.Year()<1||o.At.Year()>9999{return PathValidationReport{},errors.New("explicit UTC evaluation time required")}
	if len(o.AnchorFingerprints)>MaxVerificationCAs||len(o.IntermediateFingerprints)>MaxVerificationCAs-len(o.AnchorFingerprints){return PathValidationReport{},errors.New("verification CA limit exceeded")}
	var usage smx509.ExtKeyUsage
	switch o.Profile{
	case "signature":usage=smx509.ExtKeyUsageAny
	case "timestamping":usage=smx509.ExtKeyUsageTimeStamping
	case "code-signing":usage=smx509.ExtKeyUsageCodeSigning
	case "client-authentication":usage=smx509.ExtKeyUsageClientAuth
	case "server-authentication":usage=smx509.ExtKeyUsageServerAuth
	default:return PathValidationReport{},errors.New("unknown technical verification profile")
	}
	if (o.Profile=="server-authentication")!=(strings.TrimSpace(o.DNSName)!="")||len(o.DNSName)>253{return PathValidationReport{},errors.New("DNS name required only for server-authentication")}
	r,der,err:=ParseCertificate(input);if err!=nil{return PathValidationReport{},err}
	leaf,err:=smx509.ParseCertificate(der);if err!=nil{return PathValidationReport{},err}
	report:=PathValidationReport{LeafSHA256:r.FingerprintSHA256,EvaluationTime:o.At,Profile:o.Profile,PathStatus:"NOT_ESTABLISHED",UsageStatus:"NOT_EVALUATED",RevocationStatus:"NOT_CHECKED",TrustStatus:"NOT_ESTABLISHED",Chains:[][]string{}}
	reject:=func(reason string)(PathValidationReport,error){report.Reason=reason;return report,nil}
	if leaf.IsCA{return reject("end-entity certificate required")}
	idx,err:=s.BuildIndex();if err!=nil{return PathValidationReport{},err}
	roots,intermediates:=smx509.NewCertPool(),smx509.NewCertPool()
	seen:=map[string]bool{}
	anchors:=map[string]bool{}
	total:=len(der)
	add:=func(fp string,pool *smx509.CertPool,anchor bool)error{
		if seen[fp]||fp==r.FingerprintSHA256{return errors.New("duplicate CA role or leaf reused as CA")}
		record,err:=idx.Find(fp);if err!=nil{return err}
		raw,err:=readRegular(filepath.Join(s.root,"certificates",fp+".der"),MaxCertificateInput);if err!=nil{return err}
		if digest(raw)!=record.FingerprintSHA256{return errors.New("inventory changed during path validation")}
		if len(raw)>MaxGraphDERBytes-total{return errors.New("verification DER byte limit exceeded")}
		c,err:=smx509.ParseCertificate(raw);if err!=nil{return err}
		if !c.BasicConstraintsValid||!c.IsCA||(c.KeyUsage!=0&&c.KeyUsage&smx509.KeyUsageCertSign==0)||len(c.UnhandledCriticalExtensions)>0{return fmt.Errorf("ineligible CA: %s",fp)}
		pool.AddCert(c)
		total+=len(raw);seen[fp]=true
		if anchor{anchors[fp]=true}
		return nil
	}
	for _,fp:=range o.AnchorFingerprints{if err:=add(fp,roots,true);err!=nil{return PathValidationReport{},err}}
	for _,fp:=range o.IntermediateFingerprints{if err:=add(fp,intermediates,false);err!=nil{return PathValidationReport{},err}}
	if len(anchors)==0{return reject("no explicit anchors")}
	// Require signing key usage for signing profiles rather than accepting an
	// absent extension as unrestricted. This is a conservative local rule.
	switch o.Profile{
	case "signature","timestamping","code-signing":
		if leaf.KeyUsage&(smx509.KeyUsageDigitalSignature|smx509.KeyUsageContentCommitment)==0{return reject("leaf lacks explicit signing key usage")}
	}
	if o.Profile=="code-signing"{
		found:=false
		for _,v:=range leaf.ExtKeyUsage{if v==smx509.ExtKeyUsageCodeSigning{found=true}}
		if !found{return reject("leaf lacks explicit code-signing EKU")}
	}
	if o.Profile=="timestamping"{
		critical:=false
		for _,ext:=range leaf.Extensions{if ext.Id.String()=="2.5.29.37"&&ext.Critical{critical=true}}
		if !critical||len(leaf.ExtKeyUsage)!=1||leaf.ExtKeyUsage[0]!=smx509.ExtKeyUsageTimeStamping||len(leaf.UnknownExtKeyUsage)!=0{return reject("timestamping requires critical exclusive timeStamping EKU")}
	}
	chains,err:=leaf.Verify(smx509.VerifyOptions{Roots:roots,Intermediates:intermediates,CurrentTime:o.At,KeyUsages:[]smx509.ExtKeyUsage{usage},DNSName:o.DNSName,MaxConstraintComparisions:10000})
	if err!=nil{return reject("certificate path rejected by smx509")}
	if len(chains)>MaxCandidatePaths{return PathValidationReport{},errors.New("verified chain limit exceeded")}
	for _,chain:=range chains{
		if len(chain)<2||len(chain)>MaxPathDepth||!anchors[digest(chain[len(chain)-1].Raw)]{continue}
		fps:=make([]string,0,len(chain))
		valid:=true
		for i,c:=range chain{
			fp:=digest(c.Raw)
			if i==0&&fp!=r.FingerprintSHA256||i>0&&!seen[fp]||i>0&&i<len(chain)-1&&anchors[fp]{valid=false;break}
			fps=append(fps,fp)
			if i>0{
				rec,err:=idx.Find(fp);if err!=nil{return PathValidationReport{},err}
				edge,ok:=checkDirectIssuer(chain[i-1],c,rec)
				if !ok||edge.DirectIssuerStatus!="MATCHED"{valid=false;break}
			}
		}
		if valid{report.Chains=append(report.Chains,fps)}
	}
	if len(report.Chains)==0{return reject("no chain satisfies explicit registry issuer constraints")}
	sort.Slice(report.Chains,func(i,j int)bool{return strings.Join(report.Chains[i],"/")<strings.Join(report.Chains[j],"/")})
	report.PathStatus="VALID_UNDER_EXPLICIT_CA_SET"
	if o.Profile=="signature"{report.UsageStatus="GENERIC_SIGNING_KEY_USAGE_ONLY"}else{report.UsageStatus="TECHNICAL_PROFILE_MATCHED"}
	return report,nil
}
