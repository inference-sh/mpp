package mpp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Store records spent payment credentials so each one buys exactly one request.
//
// The middleware claims a credential before settling it and keeps the claim once
// the request is served. A second request carrying the same credential fails to
// claim and is rejected without reaching the payment provider.
//
// Implementations must be safe for concurrent use. Deployments that run more than
// one server instance must share one Store between them (Redis SET NX, a database
// unique key, ...): with a per-instance store a credential can be spent once per
// instance.
type Store interface {
	// Claim atomically records key as spent. It returns false if key is already
	// claimed. The claim must be kept until at least expires; a zero expires
	// means the claim never expires.
	Claim(ctx context.Context, key string, expires time.Time) (bool, error)

	// Release removes a claim. The middleware calls it when settlement or the
	// OnPayment hook fails, so the client can retry the same credential.
	Release(ctx context.Context, key string) error
}

// ReplayKeyer is optionally implemented by a Method to tell apart distinct
// payments made against the same challenge.
//
// Challenge IDs are deterministic: clients quoted the same price in the same
// second receive the same ID. ReplayKey returns whatever identifies the payment
// within that challenge (for Stripe, the SPT), so those clients do not collide.
// Two credentials with equal challenge ID and equal ReplayKey are the same
// payment; the value must therefore cover everything the method uses to
// deduplicate settlement.
//
// Methods that do not implement ReplayKeyer are keyed on the challenge ID alone.
type ReplayKeyer interface {
	ReplayKey(cred *Credential) (string, error)
}

// storeKey derives the Store key for a credential. The key is hashed so payment
// tokens are never written to the store.
func storeKey(method Method, cred *Credential) (string, error) {
	var discriminator string
	if rk, ok := method.(ReplayKeyer); ok {
		d, err := rk.ReplayKey(cred)
		if err != nil {
			return "", err
		}
		discriminator = d
	}

	h := sha256.New()
	for _, part := range [3]string{method.Name(), cred.Challenge.ID, discriminator} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "mpp:" + hex.EncodeToString(h.Sum(nil)), nil
}

type settlementCtxKey struct{}

// withClaim marks ctx as belonging to a request whose credential has been
// claimed in a Store.
func withClaim(ctx context.Context) context.Context {
	return context.WithValue(ctx, settlementCtxKey{}, true)
}

// hasClaim reports whether the credential being verified is already protected
// against reuse by a Store claim.
func hasClaim(ctx context.Context) bool {
	v, _ := ctx.Value(settlementCtxKey{}).(bool)
	return v
}

// memoryStoreGrace is how long MemoryStore keeps a claim past its expiry, so a
// request that passed the expiry check just before the deadline cannot reclaim.
const memoryStoreGrace = time.Minute

// MemoryStore is an in-process Store. It is the default when Config.Store is nil
// and is only sufficient for a single server instance: claims are not shared
// between processes and are lost on restart.
type MemoryStore struct {
	mu        sync.Mutex
	claims    map[string]time.Time
	lastSweep time.Time
	now       func() time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		claims: make(map[string]time.Time),
		now:    time.Now,
	}
}

func (m *MemoryStore) Claim(_ context.Context, key string, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.sweep(now)

	if _, claimed := m.claims[key]; claimed {
		return false, nil
	}
	m.claims[key] = expires
	return true, nil
}

func (m *MemoryStore) Release(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.claims, key)
	return nil
}

// sweep drops claims whose expiry passed more than memoryStoreGrace ago.
// Presence in the map is what marks a key as claimed, so sweeping only bounds memory.
func (m *MemoryStore) sweep(now time.Time) {
	if now.Sub(m.lastSweep) < memoryStoreGrace {
		return
	}
	m.lastSweep = now
	for key, expires := range m.claims {
		if !expires.IsZero() && now.After(expires.Add(memoryStoreGrace)) {
			delete(m.claims, key)
		}
	}
}
