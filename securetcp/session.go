package securetcp

import (
	"encoding/hex"
	"sync"
	"time"
)

// SessionTicket is an in-memory resumption ticket. Store it only in trusted memory.
type SessionTicket struct {
	ID        []byte
	Secret    []byte
	ExpiresAt time.Time
}

func (t *SessionTicket) clone() *SessionTicket {
	if t == nil {
		return nil
	}
	return &SessionTicket{ID: append([]byte(nil), t.ID...), Secret: append([]byte(nil), t.Secret...), ExpiresAt: t.ExpiresAt}
}

func (t *SessionTicket) valid(now time.Time) bool {
	return t != nil && len(t.ID) == 16 && len(t.Secret) == 32 && now.Before(t.ExpiresAt)
}

type sessionCacheEntry struct {
	clientPublic []byte
	ticket       *SessionTicket
}

type sessionCache struct {
	mu sync.Mutex
	m  map[string]sessionCacheEntry
}

func newSessionCache() *sessionCache {
	return &sessionCache{m: make(map[string]sessionCacheEntry)}
}

func (c *sessionCache) put(clientPublic []byte, ticket *SessionTicket) {
	if c == nil || ticket == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(time.Now())
	c.m[hex.EncodeToString(ticket.ID)] = sessionCacheEntry{clientPublic: append([]byte(nil), clientPublic...), ticket: ticket.clone()}
}

func (c *sessionCache) get(id []byte) (sessionCacheEntry, bool) {
	if c == nil {
		return sessionCacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.gcLocked(now)
	entry, ok := c.m[hex.EncodeToString(id)]
	if !ok || !entry.ticket.valid(now) {
		return sessionCacheEntry{}, false
	}
	return sessionCacheEntry{clientPublic: append([]byte(nil), entry.clientPublic...), ticket: entry.ticket.clone()}, true
}

func (c *sessionCache) delete(id []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, hex.EncodeToString(id))
}

func (c *sessionCache) gcLocked(now time.Time) {
	for id, entry := range c.m {
		if !entry.ticket.valid(now) {
			delete(c.m, id)
		}
	}
}

func newTicket(ttl time.Duration) (*SessionTicket, error) {
	id, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	secret, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	return &SessionTicket{ID: id, Secret: secret, ExpiresAt: time.Now().Add(ttl)}, nil
}
