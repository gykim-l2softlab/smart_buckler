package store

import (
	"context"
	"testing"
	"time"
)

func TestDecoysRoundTrip(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	got, err := s.Decoys(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty store: %v %v", got, err)
	}

	t0 := time.UnixMilli(1_800_000_000_000)
	if err := s.ReplaceDecoys(ctx, []Decoy{{"/b-1/", t0}, {"/a-1/", t0}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceDecoys(ctx, []Decoy{{"/c-1/", t0}, {"/a-1/", t0}}); err != nil {
		t.Fatal(err)
	}
	got, err = s.Decoys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != "/a-1/" || got[1].Path != "/c-1/" || !got[0].CreatedAt.Equal(t0) {
		t.Errorf("decoys = %+v", got)
	}
}

func TestBlocks(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.UnixMilli(1_800_000_000_000)

	for _, b := range []Block{
		{SessionID: "198.51.100.1", Until: now.Add(time.Hour), Reason: "trap", CreatedAt: now},
		{SessionID: "198.51.100.2", Until: now.Add(-time.Second), Reason: "trap", CreatedAt: now},
	} {
		if err := s.SaveBlock(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	// Extending an existing block updates until.
	if err := s.SaveBlock(ctx, Block{SessionID: "198.51.100.1", Until: now.Add(2 * time.Hour), Reason: "trap", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ActiveBlocks(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SessionID != "198.51.100.1" || !got[0].Until.Equal(now.Add(2*time.Hour)) {
		t.Errorf("active = %+v", got)
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM blocks").Scan(&n); err != nil || n != 1 {
		t.Errorf("expired block not deleted: %d rows (err %v)", n, err)
	}
}
