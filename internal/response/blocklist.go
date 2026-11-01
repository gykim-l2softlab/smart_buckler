// Package response decides and applies responses to suspicious sessions.
package response

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

// BlockStore persists blocks so they survive restarts.
type BlockStore interface {
	SaveBlock(ctx context.Context, b store.Block) error
	ActiveBlocks(ctx context.Context, now time.Time) ([]store.Block, error)
	DeleteBlock(ctx context.Context, sessionID string) (bool, error)
}

// Blocklist holds blocked sessions in memory and mirrors them to a BlockStore.
// Lookups never touch the store.
type Blocklist struct {
	store BlockStore
	log   *slog.Logger
	now   func() time.Time

	mu    sync.RWMutex
	until map[string]time.Time
}

const persistTimeout = 2 * time.Second

// NewBlocklist loads active blocks from st.
func NewBlocklist(ctx context.Context, st BlockStore, log *slog.Logger, now func() time.Time) (*Blocklist, error) {
	blocks, err := st.ActiveBlocks(ctx, now())
	if err != nil {
		return nil, fmt.Errorf("load blocks: %w", err)
	}
	b := &Blocklist{store: st, log: log, now: now, until: make(map[string]time.Time, len(blocks))}
	for _, blk := range blocks {
		b.until[blk.SessionID] = blk.Until
	}
	return b, nil
}

// Blocked reports whether id is currently blocked.
func (b *Blocklist) Blocked(id string) bool {
	b.mu.RLock()
	until, ok := b.until[id]
	b.mu.RUnlock()
	return ok && b.now().Before(until)
}

// Block blocks id for d. The block takes effect in memory immediately; a
// persistence failure is logged and does not undo it.
func (b *Blocklist) Block(ctx context.Context, id string, d time.Duration, reason string) {
	now := b.now()
	until := now.Add(d)

	b.mu.Lock()
	// Blocks are rare, so sweeping expired entries here keeps memory bounded.
	for k, u := range b.until {
		if !now.Before(u) {
			delete(b.until, k)
		}
	}
	b.until[id] = until
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, persistTimeout)
	defer cancel()
	if err := b.store.SaveBlock(ctx, store.Block{SessionID: id, Until: until, Reason: reason, CreatedAt: now}); err != nil {
		b.log.Error("persist block", "err", err, "session", id)
	}
}

// Unblock lifts a block in memory and in the store. It reports whether id
// was blocked in either.
func (b *Blocklist) Unblock(ctx context.Context, id string) (bool, error) {
	b.mu.Lock()
	_, inMemory := b.until[id]
	delete(b.until, id)
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, persistTimeout)
	defer cancel()
	stored, err := b.store.DeleteBlock(ctx, id)
	if err != nil {
		return inMemory, fmt.Errorf("unblock %s: %w", id, err)
	}
	return inMemory || stored, nil
}
