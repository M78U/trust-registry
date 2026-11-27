package tufclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/M78U/trust-registry/pkg/review"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// RootRecoveryOptions requires the same independent trust configuration as
// the strict client, plus explicit selection of the exact archived head.
type RootRecoveryOptions struct {
	StateDir string
	InitialRootSHA256 string
	Authority *review.Authority
	ExpectedHeadSHA256 string
}

type RootRecoveryReport struct {
	Status string `json:"status"`
	PreviousRootVersion int64 `json:"previousRootVersion"`
	RootChain RootChainReport `json:"rootChain"`
	CacheAdvanced bool `json:"cacheAdvanced"`
	RequiresOnlineRefresh bool `json:"requiresOnlineRefresh"`
}

// RecoverRootCache repairs only an exact older cached root in an intact,
// independently verified archive. It is not an installation or release
// approval. Timestamp/snapshot/targets and installed evidence are untouched.
func RecoverRootCache(o RootRecoveryOptions) (RootRecoveryReport, error) {
	if o.StateDir == "" || !hashPattern.MatchString(o.InitialRootSHA256) || !hashPattern.MatchString(o.ExpectedHeadSHA256) || o.Authority == nil || !hashPattern.MatchString(o.Authority.SHA256()) {
		return RootRecoveryReport{}, errors.New("strict state, independent root/authority and expected archived head SHA-256 required")
	}
	dir, err := filepath.Abs(o.StateDir)
	if err != nil { return RootRecoveryReport{}, err }
	if err := regularDir(dir); err != nil { return RootRecoveryReport{}, err }
	lock := filepath.Join(dir, ".lock")
	if err := os.Mkdir(lock, 0700); err != nil { return RootRecoveryReport{}, fmt.Errorf("TUF state locked: %w", err) }
	defer os.Remove(lock)
	raw, err := readRegular(filepath.Join(dir, "configuration.json"), 16384)
	if err != nil { return RootRecoveryReport{}, err }
	var cfg stateConfig
	if err := json.Unmarshal(raw, &cfg); err != nil { return RootRecoveryReport{}, err }
	canonical, err := json.Marshal(cfg)
	if err != nil || !bytes.Equal(raw, canonical) || cfg.SchemaVersion != "1" || cfg.InitialRootSHA256 != o.InitialRootSHA256 || cfg.ReviewAuthoritySHA256 != o.Authority.SHA256() {
		return RootRecoveryReport{}, errors.New("state identity or review authority mismatch")
	}
	metaDir := filepath.Join(dir, "metadata")
	if err := regularDir(metaDir); err != nil { return RootRecoveryReport{}, err }
	rootPath := filepath.Join(metaDir, "root.json")
	cached, err := readRegular(rootPath, maxRoot)
	if err != nil { return RootRecoveryReport{}, err }
	at := time.Now().UTC()
	chain, err := readNumberedRootArchive(filepath.Join(dir, "roots"), o.InitialRootSHA256, at)
	if err != nil { return RootRecoveryReport{}, err }
	// Expired archived roots may only be used to resume online rotation.
	_, report, err := validateRootChain(chain, o.InitialRootSHA256, at, false)
	if err != nil { return RootRecoveryReport{}, err }
	if report.CurrentRootSHA256 != o.ExpectedHeadSHA256 { return RootRecoveryReport{}, errors.New("archived head does not match selected digest") }
	for _, raw := range chain {
		m, err := metadata.Root().FromBytes(raw)
		if err != nil { return RootRecoveryReport{}, err }
		if err := strictRootProfile(m, o.Authority); err != nil { return RootRecoveryReport{}, err }
	}
	if err := checkInstalledRootBaseline(dir, o.InitialRootSHA256, chain); err != nil { return RootRecoveryReport{}, err }
	var previous int64
	for i, raw := range chain {
		if bytes.Equal(cached, raw) { previous = int64(i+1); break }
	}
	if previous == 0 { return RootRecoveryReport{}, errors.New("cached root is not an exact archived prefix; refusing repair") }
	result := RootRecoveryReport{Status:"ROOT_CACHE_ALREADY_AT_ARCHIVED_HEAD", PreviousRootVersion:previous, RootChain:report, RequiresOnlineRefresh:true}
	if previous == report.RootVersion { return result, nil }

	// A complete file is staged outside metadata and the numbered archive,
	// then replaced by rename. Do not delete any rollback metadata.
	f, err := os.CreateTemp(dir, ".root-cache-stage-")
	if err != nil { return RootRecoveryReport{}, err }
	defer os.Remove(f.Name())
	if _, err = f.Write(chain[len(chain)-1]); err == nil { err = f.Sync() }
	closeErr := f.Close()
	if err == nil { err = closeErr }
	if err != nil { return RootRecoveryReport{}, err }
	if time.Now().UTC().Before(at) { return RootRecoveryReport{}, errors.New("clock moved backward during root recovery") }
	if err := os.Rename(f.Name(), rootPath); err != nil { return RootRecoveryReport{}, err }
	result.Status = "ROOT_CACHE_ADVANCED_TO_VERIFIED_ARCHIVED_HEAD"
	result.CacheAdvanced = true
	return result, nil
}
