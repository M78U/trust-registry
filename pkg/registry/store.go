package registry

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/M78U/trust-registry/schemas"
)

const maxRecordBytes = 64 << 10

// Store is a local candidate inventory, not a trust store. The operator must
// control the directory and exclude concurrent external mutation. Validation
// detects incomplete imports; it does not authenticate the inventory.
type Store struct { root string }

func OpenStore(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" { return nil, errors.New("registry directory is required") }
	abs, err := filepath.Abs(root)
	if err != nil { return nil, err }
	return &Store{root: abs}, nil
}

func validFingerprint(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s { return false }
	_, err := hex.DecodeString(s)
	return err == nil
}

func canonicalJSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil { return nil, err }
	return append(b, '\n'), nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("invalid file type or size: %s", path)
	}
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	opened, err := f.Stat()
	if err != nil { return nil, err }
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) { return nil, errors.New("file changed while opening") }
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil { return nil, err }
	if int64(len(b)) > limit { return nil, errors.New("file exceeds size limit") }
	return b, nil
}

func ensureDir(path string, create bool) error {
	if create {
		if err := os.MkdirAll(path, 0755); err != nil { return err }
	}
	info, err := os.Lstat(path)
	if err != nil { return err }
	if !info.IsDir() { return fmt.Errorf("not a regular directory: %s", path) }
	return nil
}

func (s *Store) dirs(create bool) error {
	if err := ensureDir(s.root, create); err != nil { return err }
	for _, dir := range []string{"certificates", "provenance"} {
		if err := ensureDir(filepath.Join(s.root, dir), create); err != nil { return err }
	}
	return nil
}

// writeImmutable installs complete files without replacing an existing path.
// Same-content collisions are idempotent; different content is an error.
// Hard-link support on the local filesystem is required.
func writeImmutable(path string, data []byte) error {
	if existing, err := readRegular(path, int64(len(data))); err == nil {
		if bytes.Equal(existing, data) { return nil }
		return fmt.Errorf("immutable content conflict: %s", path)
	} else if !errors.Is(err, fs.ErrNotExist) { return err }
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil { return err }
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil { err = f.Sync() }
	closeErr := f.Close()
	if err != nil { return err }
	if closeErr != nil { return closeErr }
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			existing, readErr := readRegular(path, int64(len(data)))
			if readErr == nil && bytes.Equal(existing, data) { return nil }
		}
		return fmt.Errorf("install immutable file: %w", err)
	}
	return nil
}

type ImportResult struct {
	Certificate CertificateRecord `json:"certificate"`
	Provenance ProvenanceRecord `json:"provenance"`
	ProvenanceID string `json:"provenanceId"`
}

// Import records only CA candidates. Distinct observations are append-only.
// A crash between file installations may leave an incomplete inventory; rerun
// import to recover or repair manually. Validate must pass before any release.
func (s *Store) Import(input []byte, source string, at time.Time) (ImportResult, error) {
	record, provenance, der, err := ImportCandidate(input, source, at)
	if err != nil { return ImportResult{}, err }
	return s.importRecords(record, provenance, der)
}

func validateImportRecords(record CertificateRecord,provenance ProvenanceRecord)error{
 if !record.IsCA{return errors.New("persistent import accepts CA candidates only")}
 meta,err:=canonicalJSON(record);if err!=nil{return err}
 p,err:=canonicalJSON(provenance);if err!=nil{return err}
 if len(meta)>maxRecordBytes||len(p)>maxRecordBytes{return errors.New("metadata too large")}
 if err:=schemas.ValidateJSON(schemas.Certificate,meta);err!=nil{return err}
 return schemas.ValidateJSON(schemas.Provenance,p)
}

func (s *Store) importRecords(record CertificateRecord,provenance ProvenanceRecord,der []byte)(ImportResult,error){
 if !record.IsCA { return ImportResult{}, errors.New("persistent import accepts CA candidates only") }
	meta, err := canonicalJSON(record)
	if err != nil { return ImportResult{}, err }
	p, err := canonicalJSON(provenance)
	if err != nil { return ImportResult{}, err }
	if len(meta) > maxRecordBytes || len(p) > maxRecordBytes { return ImportResult{}, errors.New("metadata too large") }
	if err := schemas.ValidateJSON(schemas.Certificate,meta); err != nil { return ImportResult{},err }
	if err := schemas.ValidateJSON(schemas.Provenance,p); err != nil { return ImportResult{},err }
	if err := s.dirs(true); err != nil { return ImportResult{}, err }
	fp := record.FingerprintSHA256
	id := digest(p)
	if err := writeImmutable(filepath.Join(s.root, "certificates", fp+".der"), der); err != nil { return ImportResult{}, err }
	if err := writeImmutable(filepath.Join(s.root, "certificates", fp+".json"), meta); err != nil { return ImportResult{}, err }
	if err := writeImmutable(filepath.Join(s.root, "provenance", id+".json"), p); err != nil { return ImportResult{}, err }
	return ImportResult{record, provenance, id}, nil
}

// Find verifies content address and derived metadata before returning a record.
func (s *Store) Find(fp string) (CertificateRecord, error) {
	if !validFingerprint(fp) { return CertificateRecord{}, errors.New("expected lowercase SHA-256 fingerprint") }
	if err := s.dirs(false); err != nil { return CertificateRecord{}, err }
	der, err := readRegular(filepath.Join(s.root,"certificates",fp+".der"), MaxCertificateInput)
	if err != nil { return CertificateRecord{}, err }
	record, parsed, err := ParseCertificate(der)
	if err != nil { return CertificateRecord{}, err }
	if !bytes.Equal(parsed, der) || record.FingerprintSHA256 != fp || !record.IsCA {
		return CertificateRecord{}, errors.New("certificate content address, format or CA classification mismatch")
	}
	meta, err := readRegular(filepath.Join(s.root,"certificates",fp+".json"), maxRecordBytes)
	if err != nil { return CertificateRecord{}, err }
	expected, err := canonicalJSON(record)
	if err != nil { return CertificateRecord{}, err }
	if !bytes.Equal(meta, expected) { return CertificateRecord{}, errors.New("certificate metadata mismatch") }
	if err:=schemas.ValidateJSON(schemas.Certificate,meta);err!=nil { return CertificateRecord{},err }
	return record, nil
}

func (s *Store) List() ([]CertificateRecord, error) {
	if err := s.dirs(false); err != nil { return nil, err }
	entries, err := os.ReadDir(filepath.Join(s.root, "certificates"))
	if err != nil { return nil, err }
	records := make([]CertificateRecord, 0)
	seen := make(map[string]bool)
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		fp := strings.TrimSuffix(e.Name(), ext)
		if !e.Type().IsRegular() || !validFingerprint(fp) || (ext != ".json" && ext != ".der") {
			return nil, fmt.Errorf("unexpected certificate inventory entry: %s", e.Name())
		}
		if seen[fp] { continue }
		seen[fp] = true
		rec, err := s.Find(fp)
		if err != nil { return nil, fmt.Errorf("%s: %w", fp, err) }
		records = append(records, rec)
	}
	sort.Slice(records,func(i,j int)bool{return records[i].FingerprintSHA256 < records[j].FingerprintSHA256})
	return records, nil
}

type ProvenanceEntry struct {
	ID string `json:"id"`
	Record ProvenanceRecord `json:"record"`
}

func readProvenance(path, id string) (ProvenanceRecord,error) {
	var p ProvenanceRecord
	b, err := readRegular(path,maxRecordBytes)
	if err != nil { return p,err }
	if digest(b) != id { return p,errors.New("provenance content address mismatch") }
	if err:=schemas.ValidateJSON(schemas.Provenance,b);err!=nil { return p,err }
	if err := json.Unmarshal(b,&p); err != nil { return p,err }
	expected, err := canonicalJSON(p)
	if err != nil { return p,err }
	if !bytes.Equal(b,expected) { return p,errors.New("non-canonical or unknown provenance fields") }
	if p.SchemaVersion != "1" || !validFingerprint(p.CertificateSHA256) || !validFingerprint(p.SourceFileSHA256) ||
		p.SourceType != "UNVERIFIED_PUBLIC_SOURCE" || p.ReviewStatus != "CANDIDATE" ||
		p.ReviewEvidence == nil || len(p.ReviewEvidence) != 0 || p.RedistributionStatus != "NOT_REVIEWED" ||
		p.RecordedAt.IsZero() || p.RecordedAt.Location() != time.UTC {
		return p,errors.New("invalid candidate provenance fields")
	}
	if err := validateSourceURL(p.SourceURL); err != nil { return p,err }
	return p,nil
}

func (s *Store) allProvenance() ([]ProvenanceEntry,error) {
	if err := s.dirs(false); err != nil { return nil,err }
	entries,err := os.ReadDir(filepath.Join(s.root,"provenance"))
	if err != nil { return nil,err }
	result := make([]ProvenanceEntry,0)
	for _,e := range entries {
		id := strings.TrimSuffix(e.Name(),".json")
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(),".json") || !validFingerprint(id) {
			return nil,fmt.Errorf("unexpected provenance entry: %s",e.Name())
		}
		p,err := readProvenance(filepath.Join(s.root,"provenance",e.Name()),id)
		if err != nil { return nil,fmt.Errorf("%s: %w",id,err) }
		result = append(result,ProvenanceEntry{id,p})
	}
	return result,nil
}

// Provenance returns candidate source assertions, not verified evidence.
func (s *Store) Provenance(fp string) ([]ProvenanceEntry,error) {
	if _,err := s.Find(fp); err != nil { return nil,err }
	all,err := s.allProvenance()
	if err != nil { return nil,err }
	result := make([]ProvenanceEntry,0)
	for _,p := range all { if p.Record.CertificateSHA256 == fp { result=append(result,p) } }
	if len(result)==0 { return nil,errors.New("certificate lacks provenance") }
	return result,nil
}

type ValidationReport struct {
	Certificates int `json:"certificates"`
	ProvenanceRecords int `json:"provenanceRecords"`
}

// validatedInventory checks the complete local inventory once and returns the
// exact records checked. No assertion of source authenticity is made.
func (s *Store) validatedInventory() ([]CertificateRecord, []ProvenanceEntry, error) {
	certs, err := s.List()
	if err != nil { return nil, nil, err }
	sources, err := s.allProvenance()
	if err != nil { return nil, nil, err }
	counts := make(map[string]int, len(certs))
	for _, c := range certs { counts[c.FingerprintSHA256] = 0 }
	for _, p := range sources {
		fp := p.Record.CertificateSHA256
		if _, ok := counts[fp]; !ok { return nil, nil, fmt.Errorf("orphan provenance: %s", p.ID) }
		counts[fp]++
	}
	for _, c := range certs {
		if counts[c.FingerprintSHA256] == 0 { return nil, nil, fmt.Errorf("certificate lacks provenance: %s", c.FingerprintSHA256) }
	}
	return certs, sources, nil
}

// Validate checks canonical records, content addresses and cross references.
// It does not authenticate asserted sources or validate certificate paths.
func (s *Store) Validate() (ValidationReport, error) {
	certs, sources, err := s.validatedInventory()
	if err != nil { return ValidationReport{}, err }
	return ValidationReport{len(certs), len(sources)}, nil
}

// Init initializes a fresh empty local inventory. It does not repair an
// existing partial inventory or create any trust records.
func (s *Store) Init() (ValidationReport,error) {
	if s==nil { return ValidationReport{},errors.New("inventory required") }
	if err:=ensureDir(s.root,true);err!=nil { return ValidationReport{},err }
	entries,err:=os.ReadDir(s.root)
	if err!=nil { return ValidationReport{},err }
	if len(entries)==0 {
		if err:=s.dirs(true);err!=nil { return ValidationReport{},err }
	}
	return s.Validate()
}
