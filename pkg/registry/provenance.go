package registry

import (
	"errors"
	"net/url"
	"time"
)

type ProvenanceRecord struct {
	SchemaVersion string `json:"schemaVersion"`
	CertificateSHA256 string `json:"certificateSHA256"`
	SourceURL string `json:"sourceURL"`
	SourceType string `json:"sourceType"`
	RecordedAt time.Time `json:"recordedAt"`
	SourceFileSHA256 string `json:"sourceFileSHA256"`
	ReviewStatus string `json:"reviewStatus"`
	ReviewEvidence []string `json:"reviewEvidence"`
	RedistributionStatus string `json:"redistributionStatus"`
}

// ImportCandidate creates an unreviewed record only. source is an asserted
// location; no network requests are made and no retrieval is claimed.
func ImportCandidate(input []byte, source string, recordedAt time.Time) (CertificateRecord, ProvenanceRecord, []byte, error) {
	if err := validateSourceURL(source); err != nil {
		return CertificateRecord{}, ProvenanceRecord{}, nil, err
	}
	if recordedAt.IsZero() {
		return CertificateRecord{}, ProvenanceRecord{}, nil, errors.New("recordedAt is required")
	}
	record, der, err := ParseCertificate(input)
	if err != nil {
		return CertificateRecord{}, ProvenanceRecord{}, nil, err
	}
	return record, ProvenanceRecord{
		SchemaVersion: "1",
		CertificateSHA256: record.FingerprintSHA256,
		SourceURL: source,
		SourceType: "UNVERIFIED_PUBLIC_SOURCE",
		RecordedAt: recordedAt.UTC(),
		SourceFileSHA256: digest(input),
		ReviewStatus: "CANDIDATE",
		ReviewEvidence: []string{},
		RedistributionStatus: "NOT_REVIEWED",
	}, der, nil
}

func validateSourceURL(source string) error {
	if len(source) > 4096 { return errors.New("source URL too long") }
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return errors.New("source must be a public HTTPS URL without credentials, query or fragment")
	}
	return nil
}
