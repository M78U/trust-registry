package registry

import (
	"bytes"
	"errors"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/emmansun/gmsm/smx509"
)

const MaxIssuerCandidates = 256

// IssuerCandidate describes one direct relationship, not a trusted path.
// Matching names or key identifiers is only discovery evidence.
type IssuerCandidate struct {
	Certificate CertificateRecord `json:"certificate"`
	IssuerDNMatch bool `json:"issuerDNMatch"`
	AKISKIMatch bool `json:"akiSkiMatch"`
	KeyIdentifierConflict bool `json:"keyIdentifierConflict"`
	SignatureStatus string `json:"signatureStatus"`
	DirectIssuerStatus string `json:"directIssuerStatus"`
	Reason string `json:"reason"`
}

type DiscoveryReport struct {
	CertificateSHA256 string `json:"certificateSHA256"`
	TrustStatus string `json:"trustStatus"`
	Candidates []IssuerCandidate `json:"candidates"`
}

// DiscoverIssuers searches a validated, operator-controlled local inventory.
// Exact DER DN or nonempty AKI/SKI equality admits a candidate. Equivalent
// names encoded differently may be missed. No network, OS roots or trust
// authorization. A direct issuer match does not validate a complete path.
func (s *Store) DiscoverIssuers(input []byte) (DiscoveryReport,error) {
	record,der,err:=ParseCertificate(input)
	if err!=nil { return DiscoveryReport{},err }
	child,err:=smx509.ParseCertificate(der)
	if err!=nil { return DiscoveryReport{},err }
	index,err:=s.BuildIndex()
	if err!=nil { return DiscoveryReport{},err }
	records:=index.issuerCandidates(child.Issuer.String(),hex.EncodeToString(child.AuthorityKeyId))
	report:=DiscoveryReport{record.FingerprintSHA256,"NOT_ESTABLISHED",make([]IssuerCandidate,0)}
	for _,r:=range records {
		// Never treat the exact input certificate as its own issuer candidate.
		if r.FingerprintSHA256==record.FingerprintSHA256 { continue }
		raw,err:=readRegular(filepath.Join(s.root,"certificates",r.FingerprintSHA256+".der"),MaxCertificateInput)
		if err!=nil { return DiscoveryReport{},err }
		if digest(raw)!=r.FingerprintSHA256 { return DiscoveryReport{},errors.New("inventory changed during discovery") }
		parent,err:=smx509.ParseCertificate(raw)
		if err!=nil { return DiscoveryReport{},err }
		dn:=bytes.Equal(child.RawIssuer,parent.RawSubject)
		bothIDs:=len(child.AuthorityKeyId)>0 && len(parent.SubjectKeyId)>0
		keyMatch:=bothIDs && bytes.Equal(child.AuthorityKeyId,parent.SubjectKeyId)
		if !dn && !keyMatch { continue }
		if len(report.Candidates)>=MaxIssuerCandidates { return DiscoveryReport{},fmt.Errorf("issuer candidate limit exceeded (%d)",MaxIssuerCandidates) }
		candidate:=IssuerCandidate{Certificate:r,IssuerDNMatch:dn,AKISKIMatch:keyMatch,KeyIdentifierConflict:bothIDs&&!keyMatch,SignatureStatus:"NOT_VERIFIED",DirectIssuerStatus:"NOT_ESTABLISHED"}
		// Report raw signature evidence separately from name/CA constraints.
		if err:=parent.CheckSignature(child.SignatureAlgorithm,child.RawTBSCertificate,child.Signature); err!=nil {
			candidate.Reason="signature invalid, unsupported or rejected by algorithm policy"
		} else {
			candidate.SignatureStatus="VERIFIED"
			switch {
			case !dn:
				candidate.Reason="issuer DN does not exactly match subject DN"
			case candidate.KeyIdentifierConflict:
				candidate.Reason="AKI/SKI conflict"
			case !parent.BasicConstraintsValid || !parent.IsCA:
				candidate.Reason="issuer lacks CA basic constraints"
			case parent.KeyUsage!=0 && parent.KeyUsage&smx509.KeyUsageCertSign==0:
				candidate.Reason="issuer key usage does not allow certificate signing"
			case len(parent.UnhandledCriticalExtensions)>0 || len(child.UnhandledCriticalExtensions)>0:
				candidate.Reason="unhandled critical extensions"
			default:
				if err:=child.CheckSignatureFrom(parent); err!=nil {
					candidate.Reason="direct issuer constraints or signature policy rejected"
				} else {
					candidate.DirectIssuerStatus="MATCHED"
					candidate.Reason="direct issuer evidence only; path and trust not evaluated"
				}
			}
		}
		report.Candidates=append(report.Candidates,candidate)
	}
	return report,nil
}
