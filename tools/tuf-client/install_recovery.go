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

const pendingInstallName = "pending-install.json"

// stagePendingEvidence writes outside the immutable installed directory.
// A process interruption cannot introduce a partial file into that history.
// The previous journal is replaced only by a fully verified online candidate.
func stagePendingEvidence(root string, v evidence) error {
	data, err := encodeEvidence(v)
	if err != nil { return err }
	if len(data) > maxEvidenceBytes { return errors.New("installation evidence too large") }
	path := filepath.Join(root, pendingInstallName)
	if i, err := os.Lstat(path); err == nil {
		if !i.Mode().IsRegular() { return errors.New("invalid pending installation file") }
	} else if !os.IsNotExist(err) { return err }
	f, err := os.CreateTemp(root, ".install-stage-")
	if err != nil { return err }
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil { err = f.Sync() }
	closeErr := f.Close()
	if err == nil { err = closeErr }
	if err != nil { return err }
	return os.Rename(f.Name(), path)
}

// commitPendingEvidence never replaces an installed record. If interrupted
// after the link, the remaining journal is an idempotent cleanup operation.
func commitPendingEvidence(root, dir string, v evidence, already bool) error {
	pending := filepath.Join(root, pendingInstallName)
	if !already {
		if err := os.Link(pending, filepath.Join(dir, evidenceName(v.Sequence))); err != nil { return err }
	}
	if err := os.Remove(pending); err != nil {
		return fmt.Errorf("installation committed but pending journal cleanup failed: %w", err)
	}
	return nil
}

type RecoveryOptions struct {
	StateDir          string
	InitialRootSHA256 string
	Authority         *review.Authority
	Checkpoint        *ReleaseCheckpoint
}

// RecoverPendingInstall completes only an existing, fully signed strict
// installation journal. It never performs networking, rewrites metadata,
// rolls back a root, unlocks another process or falls back to older evidence.
func RecoverPendingInstall(o RecoveryOptions) (Report, error) {
	if o.StateDir == "" || !hashPattern.MatchString(o.InitialRootSHA256) || o.Authority == nil || !hashPattern.MatchString(o.Authority.SHA256()) {
		return Report{}, errors.New("state and independent strict root/authority pins required")
	}
	var checkpoint *ReleaseCheckpoint
	if o.Checkpoint != nil {
		c := *o.Checkpoint
		if err := c.validate(); err != nil { return Report{}, err }
		checkpoint = &c
	}
	root, err := filepath.Abs(o.StateDir)
	if err != nil { return Report{}, err }
	if err := regularDir(root); err != nil { return Report{}, err }
	lock := filepath.Join(root, ".lock")
	if err := os.Mkdir(lock, 0700); err != nil { return Report{}, fmt.Errorf("TUF state locked: %w", err) }
	defer os.Remove(lock)
	cfgBytes, err := readRegular(filepath.Join(root, "configuration.json"), 16384)
	if err != nil { return Report{}, err }
	var cfg stateConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil { return Report{}, err }
	canonical, err := json.Marshal(cfg)
	if err != nil || !bytes.Equal(canonical, cfgBytes) || cfg.SchemaVersion != "1" || cfg.InitialRootSHA256 != o.InitialRootSHA256 || cfg.ReviewAuthoritySHA256 != o.Authority.SHA256() {
		return Report{}, errors.New("pending state identity or review authority mismatch")
	}
	raw, err := readRegular(filepath.Join(root, pendingInstallName), maxEvidenceBytes)
	if err != nil { return Report{}, err }
	var v evidence
	if err := json.Unmarshal(raw, &v); err != nil { return Report{}, err }
	canonical, err = encodeEvidence(v)
	if err != nil || !bytes.Equal(canonical, raw) { return Report{}, errors.New("noncanonical pending installation") }
	metaDir := filepath.Join(root, "metadata")
	if err := regularDir(metaDir); err != nil { return Report{}, err }
	for _, file := range []struct{name string; limit int64; expected []byte}{
		{"root.json", maxRoot, v.Root},
		{"timestamp.json", 16384, v.Timestamp},
		{"snapshot.json", 2_000_000, v.SnapshotMetadata},
		{"targets.json", 5_000_000, v.Targets},
	} {
		cached, err := readRegular(filepath.Join(metaDir, file.name), file.limit)
		if err != nil { return Report{}, err }
		if !bytes.Equal(cached, file.expected) { return Report{}, errors.New("pending installation differs from current metadata; no rollback") }
	}
	at := time.Now().UTC()
	chain, err := readRootArchive(root, o.InitialRootSHA256, v.Root, at, false)
	if err != nil { return Report{}, err }
	if len(chain) != len(evidenceChain(v)) || !rootPrefix(evidenceChain(v), chain) { return Report{}, errors.New("pending root chain differs from archive") }
	report, err := verifyEvidence(v, o.InitialRootSHA256, at)
	if err != nil { return Report{}, err }
	tg, err := metadata.Targets().FromBytes(v.Targets)
	if err != nil { return Report{}, err }
	sm, err := metadata.Snapshot().FromBytes(v.SnapshotMetadata)
	if err != nil { return Report{}, err }
	ts, err := metadata.Timestamp().FromBytes(v.Timestamp)
	if err != nil { return Report{}, err }
	rt, err := metadata.Root().FromBytes(v.Root)
	if err != nil { return Report{}, err }
	approval, err := checkPublicCredential(o.Authority, chain, o.InitialRootSHA256, tg.Signed.Targets[TargetName], tg.Signed.Version, tg.Signed.Expires, sm.Signed.Expires, ts.Signed.Expires, at)
	if err != nil { return Report{}, err }
	if checkpoint != nil {
		if err := checkpoint.check(v.Sequence, v.SnapshotSHA256, report.RootVersion); err != nil { return Report{}, err }
	}
	dir, already, err := checkInstallBaseline(root, o.InitialRootSHA256, v, at)
	if err != nil { return Report{}, err }
	finished := time.Now().UTC()
	if finished.Before(at) { return Report{}, errors.New("clock moved backward during recovery") }
	for _, expires := range []time.Time{rt.Signed.Expires, tg.Signed.Expires, sm.Signed.Expires, ts.Signed.Expires, report.Registry.Manifest.ExpiresAt} {
		if !finished.Before(expires) { return Report{}, errors.New("pending installation expired during recovery") }
	}
	if err := commitPendingEvidence(root, dir, v, already); err != nil { return Report{}, err }
	report.ReleaseApproval = &approval
	report.IndependentCheckpointChecked = checkpoint != nil
	report.ApplicationRollbackStatus = "CHECKED_LOCAL_INSTALLATION"
	report.RecoveredPendingInstall = true
	return report, nil
}
