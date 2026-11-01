package response

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openStore(t *testing.T, path string) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBlockExpiresAndPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "e.db")
	c := &clock{t: time.Unix(1_800_000_000, 0)}

	bl, err := NewBlocklist(ctx, openStore(t, path), discard(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	if bl.Blocked("198.51.100.1") {
		t.Fatal("blocked before Block")
	}
	bl.Block(ctx, "198.51.100.1", time.Hour, "trap")
	if !bl.Blocked("198.51.100.1") || bl.Blocked("198.51.100.2") {
		t.Fatal("unexpected blocked state")
	}

	// A new Blocklist on the same database (restart) still blocks.
	c.add(30 * time.Minute)
	restarted, err := NewBlocklist(ctx, openStore(t, path), discard(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.Blocked("198.51.100.1") {
		t.Fatal("block lost after restart")
	}

	c.add(31 * time.Minute)
	if restarted.Blocked("198.51.100.1") || bl.Blocked("198.51.100.1") {
		t.Fatal("block did not expire")
	}
}

func TestBlockSweepsExpired(t *testing.T) {
	ctx := context.Background()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	bl, err := NewBlocklist(ctx, openStore(t, filepath.Join(t.TempDir(), "e.db")), discard(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	bl.Block(ctx, "a", time.Minute, "trap")
	c.add(2 * time.Minute)
	bl.Block(ctx, "b", time.Minute, "trap")
	if len(bl.until) != 1 {
		t.Errorf("expired entry kept: %v", bl.until)
	}
}

type failingStore struct{}

func (failingStore) SaveBlock(context.Context, store.Block) error { return errors.New("disk full") }
func (failingStore) ActiveBlocks(context.Context, time.Time) ([]store.Block, error) {
	return nil, nil
}

func TestBlockSurvivesPersistFailure(t *testing.T) {
	bl, err := NewBlocklist(context.Background(), failingStore{}, discard(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	bl.Block(context.Background(), "a", time.Hour, "trap")
	if !bl.Blocked("a") {
		t.Fatal("block dropped after persist failure")
	}
}

func TestConcurrentAccess(t *testing.T) {
	bl, err := NewBlocklist(context.Background(), failingStore{}, discard(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bl.Block(context.Background(), "x", time.Hour, "trap")
				_ = bl.Blocked("x")
			}
		}()
	}
	wg.Wait()
}
