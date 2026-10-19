package live

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	abci "github.com/cometbft/cometbft/abci/types"
)

type Machine struct {
	mu       sync.RWMutex
	manifest Manifest
	dir      string
	state    *State
	pending  *State
	hash     []byte
}

func NewMachine(m Manifest, dir string) (*Machine, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	machine := &Machine{manifest: m, dir: dir, state: NewState(m)}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err == nil {
		if err = json.Unmarshal(b, machine.state); err != nil {
			return nil, err
		}
		if machine.state.Context != m.Context {
			return nil, errors.New("persisted state has different network context")
		}
		h := sha256.Sum256(JSON(machine.state))
		machine.hash = h[:]
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	h := sha256.Sum256(JSON(machine.state))
	machine.hash = h[:]
	return machine, nil
}
func (m *Machine) Info() (int64, []byte) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.Height, append([]byte{}, m.hash...)
}
func (m *Machine) Snapshot() *State { m.mu.RLock(); defer m.mu.RUnlock(); return m.state.Clone() }
func (m *Machine) CheckTx(raw []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, err := ParseTx(m.manifest, raw)
	if err != nil {
		return err
	}
	return m.state.Clone().Apply(m.manifest, t, m.state.Height+1)
}
func (m *Machine) ValidateProposal(height int64, txs [][]byte) error {
	for _, raw := range txs {
		if _, err := ParseTx(m.manifest, raw); err != nil {
			return err
		}
	}
	return nil
}
func (m *Machine) FinalizeBlock(height int64, txs [][]byte) ([]*abci.ExecTxResult, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if height != m.state.Height+1 {
		return nil, nil, fmt.Errorf("unexpected height %d after %d", height, m.state.Height)
	}
	next := m.state.Clone()
	results := make([]*abci.ExecTxResult, len(txs))
	for i, raw := range txs {
		t, err := ParseTx(m.manifest, raw)
		candidate := next.Clone()
		if err == nil {
			err = candidate.Apply(m.manifest, t, height)
		}
		if err != nil {
			results[i] = &abci.ExecTxResult{Code: 1, Log: err.Error()}
		} else {
			next = candidate
			results[i] = &abci.ExecTxResult{Code: 0}
		}
	}
	next.Height = height
	m.pending = next
	h := sha256.Sum256(JSON(next))
	return results, h[:], nil
}
func (m *Machine) Commit() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return errors.New("commit without staged block")
	}
	if err := AtomicJSON(filepath.Join(m.dir, "state.json"), m.pending); err != nil {
		return err
	}
	m.state = m.pending
	m.pending = nil
	h := sha256.Sum256(JSON(m.state))
	m.hash = h[:]
	return nil
}

// AtomicJSON fsyncs before rename; a promise is persisted before returning it.
func AtomicJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(JSON(v))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (m *Machine) Query(path string, data []byte) ([]byte, error) {
	if path != "/state" {
		return nil, errors.New("unknown query path")
	}
	return JSON(m.Snapshot()), nil
}
