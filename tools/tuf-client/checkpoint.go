package tufclient

import "errors"

// ReleaseCheckpoint is an independently retained lower bound from a
// previously authenticated strict release of the same root and authority.
// It must not be obtained from the repository being refreshed.
type ReleaseCheckpoint struct {
	Sequence       uint64 `json:"sequence"`
	SnapshotSHA256 string `json:"snapshotSHA256"`
	RootVersion    int64  `json:"rootVersion"`
}

func (c ReleaseCheckpoint) validate() error {
	if c.Sequence == 0 || c.RootVersion < 1 || !hashPattern.MatchString(c.SnapshotSHA256) {
		return errors.New("checkpoint requires positive sequence/root version and exact snapshot SHA-256")
	}
	return nil
}

func (c ReleaseCheckpoint) check(sequence uint64, hash string, rootVersion int64) error {
	if err := c.validate(); err != nil {
		return err
	}
	if sequence < c.Sequence || rootVersion < c.RootVersion {
		return errors.New("release below independent checkpoint")
	}
	if sequence == c.Sequence && (hash != c.SnapshotSHA256 || rootVersion != c.RootVersion) {
		return errors.New("same sequence conflicts with independent checkpoint")
	}
	return nil
}

// Checkpoint returns a value copy for caller-owned independent storage.
// It does not write, authenticate external storage or persist any state.
func (s *ConsumerSession) Checkpoint() (ReleaseCheckpoint, error) {
	info, err := s.Info()
	if err != nil {
		return ReleaseCheckpoint{}, err
	}
	return ReleaseCheckpoint{Sequence: info.Sequence, SnapshotSHA256: info.SnapshotSHA256, RootVersion: info.RootVersion}, nil
}
