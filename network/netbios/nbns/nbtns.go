package nbns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCleanupInterval is how often expired names are cleaned up
	DefaultCleanupInterval = 5 * time.Minute
)

// NetBIOSNameServer represents a NetBIOS Name Server
type NetBIOSNameServer struct {
	mu              sync.RWMutex
	names           map[string]*NameRecord
	secured         bool // Whether this is a secured NetBIOSNameServer
	cleanupInterval time.Duration
	cleanupQuit     chan struct{}
	cleanupDone     chan struct{}
}

// NewNetBIOSNameServer creates a new NetBIOS Name Server instance.
// Call StartCleanup to begin background TTL expiration, and StopCleanup to stop it.
func NewNetBIOSNameServer(secured bool) *NetBIOSNameServer {
	return &NetBIOSNameServer{
		names:           make(map[string]*NameRecord),
		secured:         secured,
		cleanupInterval: DefaultCleanupInterval,
	}
}

// StartCleanup begins a background goroutine that periodically removes expired name registrations.
func (n *NetBIOSNameServer) StartCleanup() {
	n.cleanupQuit = make(chan struct{})
	n.cleanupDone = make(chan struct{})
	go n.cleanupLoop()
}

// StopCleanup stops the background cleanup goroutine and waits for it to finish.
func (n *NetBIOSNameServer) StopCleanup() {
	if n.cleanupQuit != nil {
		close(n.cleanupQuit)
		<-n.cleanupDone
	}
}

// SetCleanupInterval configures the interval between cleanup cycles.
// Must be called before StartCleanup.
func (n *NetBIOSNameServer) SetCleanupInterval(interval time.Duration) {
	n.cleanupInterval = interval
}

func (n *NetBIOSNameServer) cleanupLoop() {
	defer close(n.cleanupDone)
	ticker := time.NewTicker(n.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.cleanupQuit:
			return
		case <-ticker.C:
			n.CleanExpiredNames()
		}
	}
}

// normalizeName strips trailing null bytes for consistent lookups
func normalizeName(name string) string {
	return strings.TrimRight(name, "\x00")
}

// RegisterName attempts to register a name with the name server
func (n *NetBIOSNameServer) RegisterName(name string, scopeID string, nameType NameType, owner net.IP, ttl time.Duration) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	name = normalizeName(name)
	key := nameKey(name, scopeID)

	// Check if name exists
	if record, exists := n.names[key]; exists {
		// Handle group name registration
		if record.Type == Group && nameType == Group {
			// Add new owner to group
			for _, ip := range record.Owners {
				if ip.Equal(owner) {
					return nil // Already registered
				}
			}
			record.Owners = append(record.Owners, owner)
			record.TTL = time.Now().Add(ttl)
			return nil
		}

		// Handle unique name conflicts
		if record.Type == Unique || nameType == Unique {
			return fmt.Errorf("name conflict: %s is already registered", name)
		}
	}

	// Create new record
	n.names[key] = &NameRecord{
		Name:            name,
		Type:            nameType,
		Status:          Active,
		Owners:          []net.IP{owner},
		TTL:             time.Now().Add(ttl),
		RefreshInterval: ttl,
		ScopeID:         scopeID,
	}

	return nil
}

// nameKey builds the map key from a name and scope
func nameKey(name, scopeID string) string {
	if scopeID != "" {
		return name + "." + scopeID
	}
	return name
}

// QueryName looks up a name and returns its owners, type, and remaining TTL
func (n *NetBIOSNameServer) QueryName(name string, scopeID string) ([]net.IP, NameType, time.Duration, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	name = normalizeName(name)
	key := nameKey(name, scopeID)

	record, exists := n.names[key]
	if !exists || record.Status != Active {
		return nil, Unique, 0, fmt.Errorf("name not found: %s", name)
	}

	// Make copy of owners slice to prevent external modification
	owners := make([]net.IP, len(record.Owners))
	copy(owners, record.Owners)

	remaining := time.Until(record.TTL)
	if remaining < 0 {
		remaining = 0
	}

	return owners, record.Type, remaining, nil
}

// ReleaseName removes a name registration for a specific owner
func (n *NetBIOSNameServer) ReleaseName(name string, scopeID string, owner net.IP) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	name = normalizeName(name)
	key := nameKey(name, scopeID)

	record, exists := n.names[key]
	if !exists {
		return fmt.Errorf("name not found: %s", name)
	}

	// For group names, remove only the specified owner
	if record.Type == Group {
		for i, ip := range record.Owners {
			if ip.Equal(owner) {
				record.Owners = append(record.Owners[:i], record.Owners[i+1:]...)
				// Remove record if no owners remain
				if len(record.Owners) == 0 {
					delete(n.names, key)
				}
				return nil
			}
		}
		return fmt.Errorf("owner not found for name: %s", name)
	}

	// For unique names, verify owner and remove record
	if len(record.Owners) == 0 {
		delete(n.names, key)
		return nil
	}
	if !record.Owners[0].Equal(owner) {
		return fmt.Errorf("owner mismatch for name: %s", name)
	}
	delete(n.names, key)
	return nil
}

// RefreshName updates the TTL for a name registration
func (n *NetBIOSNameServer) RefreshName(name string, scopeID string, owner net.IP) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	name = normalizeName(name)
	key := nameKey(name, scopeID)

	record, exists := n.names[key]
	if !exists {
		return fmt.Errorf("name not found: %s", name)
	}

	// Verify ownership
	ownerFound := false
	for _, ip := range record.Owners {
		if ip.Equal(owner) {
			ownerFound = true
			break
		}
	}
	if !ownerFound {
		return fmt.Errorf("owner not found for name: %s", name)
	}

	// Update TTL
	record.TTL = time.Now().Add(record.RefreshInterval)
	return nil
}

// MarkNameConflict marks a name as being in conflict
func (n *NetBIOSNameServer) MarkNameConflict(name string, scopeID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	name = normalizeName(name)
	key := nameKey(name, scopeID)

	record, exists := n.names[key]
	if !exists {
		return fmt.Errorf("name not found: %s", name)
	}

	record.Status = Conflict
	return nil
}

// CleanExpiredNames removes names that have exceeded their TTL
func (n *NetBIOSNameServer) CleanExpiredNames() {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	for name, record := range n.names {
		if now.After(record.TTL) {
			delete(n.names, name)
		}
	}
}
