package mpp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStore_ClaimIsSingleUse(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	if ok, _ := s.Claim(ctx, "k", exp); !ok {
		t.Fatal("first claim should succeed")
	}
	if ok, _ := s.Claim(ctx, "k", exp); ok {
		t.Fatal("second claim should fail")
	}
	if ok, _ := s.Claim(ctx, "other", exp); !ok {
		t.Fatal("a different key should be claimable")
	}
}

func TestMemoryStore_ReleaseAllowsReclaim(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	s.Claim(ctx, "k", exp)
	if err := s.Release(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Claim(ctx, "k", exp); !ok {
		t.Fatal("claim after release should succeed")
	}
}

func TestMemoryStore_ConcurrentClaimHasOneWinner(t *testing.T) {
	s := NewMemoryStore()
	exp := time.Now().Add(time.Minute)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := s.Claim(context.Background(), "k", exp); ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	if wins.Load() != 1 {
		t.Fatalf("expected exactly 1 winning claim, got %d", wins.Load())
	}
}

func TestMemoryStore_SweepsOnlyAfterGrace(t *testing.T) {
	now := time.Now()
	s := NewMemoryStore()
	s.now = func() time.Time { return now }
	ctx := context.Background()

	s.Claim(ctx, "expiring", now.Add(time.Minute))
	s.Claim(ctx, "forever", time.Time{})

	// just past expiry, inside the grace period: still claimed
	now = now.Add(time.Minute + memoryStoreGrace)
	if ok, _ := s.Claim(ctx, "expiring", now.Add(time.Minute)); ok {
		t.Fatal("claim inside the grace period must still be held")
	}

	// past expiry + grace: swept
	now = now.Add(memoryStoreGrace + time.Second)
	s.Claim(ctx, "trigger-sweep", now.Add(time.Minute))
	s.mu.Lock()
	_, expiringHeld := s.claims["expiring"]
	_, foreverHeld := s.claims["forever"]
	s.mu.Unlock()

	if expiringHeld {
		t.Fatal("expired claim should have been swept")
	}
	if !foreverHeld {
		t.Fatal("claim with zero expiry must never be swept")
	}
}
